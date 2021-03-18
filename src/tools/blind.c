/* 
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <libgen.h>

#include "groupsig.h"
#include "gml.h"
#include "crl.h"
#include "message.h"
#include "sysenv.h"
#include "logger.h"

#include "sys/mem.h"
#include "misc/misc.h"

#ifdef PROFILE
#include "misc/profile.h"
#endif

log_t logger;
sysenv_t *sysenv;

int main(int argc, char *argv[]) {

  int argnum = 1; // Next argument to process
  char *s_proof, *s_grpkey, *s_bldkey, *s_bldkey_pub, *s_bsig;
  groupsig_signature_t **sigs;
  groupsig_blindsig_t **bsigs;
  message_t **msgs;
  groupsig_key_t *grpkey, *bldkey;
  byte_t *b_grpkey, *b_bldkey, *b_sig, *b_bsig, *b_msg;
  uint64_t b_len, msg_len;
  int key_format, sig_format, proof_format, i, i_sig, n_sigs;
  uint8_t scheme;

  if(argc == 1) {
    fprintf(stdout, "Usage: %s <IN: scheme> <IN: group key> <OUT: blinding key> <IN: sig1> <IN: msg1>... <IN: sign> <IN: msgn>\n",
	    basename(argv[0]));
    return IOK;
  }

  /* Initialize the group signature environment */

  /* Parse scheme */
  if((groupsig_get_code_from_str(&scheme, argv[1])) == IERROR) {
    fprintf(stderr, "Error: Wrong scheme %s\n", argv[1]);
    return IERROR;
  }
  argnum++;

  if(groupsig_init(scheme, 0) == IERROR) {
    return IERROR;
  }

  /* Parse group key */
  s_grpkey = argv[argnum];
  argnum++;

  /* Parse filename for blinding key */
  s_bldkey = argv[argnum];
  argnum++;

/* Parse filename for public blinding key */
  s_bldkey_pub = argv[argnum];
  argnum++;    

  /* Import the group key */
  b_grpkey = NULL;
  if(misc_read_file_to_bytestring(s_grpkey, &b_grpkey, (uint64_t *) &b_len) == IERROR) {
    fprintf(stderr, "Error: failed to import group key.\n");
    return IERROR;
  }
  
  if(!(grpkey = groupsig_grp_key_import(scheme, b_grpkey, b_len))) {
    fprintf(stderr, "Error: invalid group key %s.\n", s_grpkey);
    return IERROR;
  }
  mem_free(b_grpkey); b_grpkey = NULL;
    
  /* Load group signatures and messages, and blind them */
  n_sigs = (argc - argnum)/2;
  i_sig = 0;
  sigs = (groupsig_signature_t **) mem_malloc(sizeof(groupsig_signature_t *)*n_sigs);
  bsigs = (groupsig_blindsig_t **) mem_malloc(sizeof(groupsig_blindsig_t *)*n_sigs);
  b_msg = NULL;
  msgs = (message_t **) mem_malloc(sizeof(message_t *)*n_sigs);

  /* By setting the blinding key to NULL, we let the first execution of blind
     create a fresh key, and then reuse the same key for the next executions. */
  bldkey = NULL;

  for(i=argnum;i<argnum+(n_sigs*2); i+=2) {
    
    /* Import i-th signature */
    b_sig = NULL;
    if(misc_read_file_to_bytestring(argv[i], &b_sig, &b_len) == IERROR) {
      fprintf(stderr, "Error: failed to read signature from %s.\n", argv[i]);
      return IERROR;
    }
    
    if(!(sigs[i_sig] = groupsig_signature_import(scheme, b_sig, (uint32_t) b_len))) {
      fprintf(stderr, "Error: failed to import signature.\n");
      return IERROR;
    }
    mem_free(b_sig); b_sig = NULL;  

    /* Initialize the i-th blinded signature */
    if(!(bsigs[i_sig] = groupsig_blindsig_init(scheme))) {
      fprintf(stderr, "Error: failed to initialize blind signature.\n");
      return IERROR;
    }

    /* Initialize i-th message */
    b_msg = NULL;
    if (misc_read_file_to_bytestring(argv[i+1], &b_msg, &msg_len) == IERROR) {
      fprintf(stderr, "Error: failed to read message file %s\n", argv[i+1]);
      return IERROR;
    }

    if (!(msgs[i_sig] = message_from_bytes(b_msg, msg_len))) {
      fprintf(stderr, "Error: failed to import message from file %s\n",
	      argv[i+1]);
      return IERROR;      
    }

    mem_free(b_msg); b_msg = NULL;

    /* Blind the signature and message */
    if(groupsig_blind(bsigs[i_sig], &bldkey, grpkey,
		      sigs[i_sig], msgs[i_sig]) == IERROR) {
      fprintf(stderr, "Error: failed to blind message.\n");
      return IERROR;
    }

    /* Export the blinded signature */
    // @todo fixed to +5 char filename
    if(!(s_bsig = (char *) mem_malloc(sizeof(char)*(strlen(argv[i])+5)))) {
      return IERROR;
    }
    
    sprintf(s_bsig, "%s.bld", argv[i]);

    b_bsig = NULL;
    if(groupsig_blindsig_export(&b_bsig, (uint32_t *) &b_len, bsigs[i_sig]) == IERROR) {
      return IERROR;
    }

    if(misc_bytes_to_file(s_bsig, b_bsig, b_len) == IERROR) {
      fprintf(stderr, "Error: Could not export blinded signature to %s.\n", s_bsig);
      return IERROR;
    }
    mem_free(b_bsig); b_bsig = NULL; 
    mem_free(s_bsig); s_bsig = NULL;
    i_sig++;
      
  }

  /* Export the full blinding key */
  b_bldkey = NULL;
  if(groupsig_bld_key_export(&b_bldkey, (uint32_t *) &b_len, bldkey) == IERROR) {
    fprintf(stderr, "Error: Could not export blinding key.\n");
    return IERROR;
  }

  if(misc_bytes_to_file(s_bldkey, b_bldkey, b_len) == IERROR) {
    fprintf(stderr, "Error: Could not write blinding key to %s.\n", s_bldkey);
    return IERROR;
  }
  mem_free(b_bldkey); b_bldkey = NULL;

  /* Export the public part of the blinding key to share with converter */
  b_bldkey = NULL;
  if(groupsig_bld_key_export_pub(&b_bldkey, (uint32_t *) &b_len, bldkey) == IERROR) {
    fprintf(stderr, "Error: Could not export public blinding key.\n");
    return IERROR;
  }

  if(misc_bytes_to_file(s_bldkey_pub, b_bldkey, b_len) == IERROR) {
    fprintf(stderr, "Error: Could not write public blinding key to %s.\n", s_bldkey_pub);
    return IERROR;
  }
  mem_free(b_bldkey); b_bldkey = NULL;  

  /* Free resources */
  for(i=0; i<n_sigs; i++) {
    groupsig_signature_free(sigs[i]); sigs[i] = NULL;
    groupsig_blindsig_free(bsigs[i]); bsigs[i] = NULL;

  }
  mem_free(sigs); sigs = NULL;
  mem_free(bsigs); bsigs = NULL;

  groupsig_clear(scheme);
  if(bldkey) { groupsig_bld_key_free(bldkey); bldkey = NULL; }
  if(grpkey) { groupsig_grp_key_free(grpkey); grpkey = NULL; }
  
  return IOK;
  
}

/* blind.c ends here */
