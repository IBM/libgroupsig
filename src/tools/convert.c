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
#include "sysenv.h"
#include "message.h"
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
  char *s_proof, *s_grpkey, *s_mgrkey, *s_bldkey, *s_csig;
  groupsig_blindsig_t **bsigs, **csigs;
  message_t **msgs;
  groupsig_key_t *grpkey, *mgrkey, *bldkey;
  byte_t *b_bldkey, *b_grpkey, *b_mgrkey, *b_bsig;
  uint64_t b_len;
  int key_format, sig_format, proof_format, i, n_sigs, sig1;
  uint8_t scheme;

  if(argc == 1) {
    fprintf(stdout, "Usage: %s <IN: scheme> <IN: group key> <IN: manager key> <IN: public blinding key> <IN: bld sig1> ... <IN: bld sign>\n",
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

  if(groupsig_init(scheme, time(NULL)) == IERROR) {
    return IERROR;
  }

    /* Parse group key */
  s_grpkey = argv[argnum];
  argnum++;

  /* Import the group key */
  b_grpkey = NULL;
  if(misc_read_file_to_bytestring(s_grpkey, &b_grpkey, &b_len) == IERROR) {
    fprintf(stderr, "Error: failed to import group key.\n");
    return IERROR;
  }
  
  if(!(grpkey = groupsig_grp_key_import(scheme, b_grpkey, (uint32_t) b_len))) {
    fprintf(stderr, "Error: invalid group key %s.\n", s_grpkey);
    return IERROR;
  }
  mem_free(b_grpkey); b_grpkey = NULL;

  /* Parse manager key */
  s_mgrkey = argv[argnum];
  argnum++;
  
  /* Import the manager key */
  b_mgrkey = NULL;
  if(misc_read_file_to_bytestring(s_mgrkey, &b_mgrkey, &b_len) == IERROR) {
    fprintf(stderr, "Error: failed to read manager key.\n");
    return IERROR;
  }
  
  if(!(mgrkey = groupsig_mgr_key_import(scheme, b_mgrkey, (uint32_t) b_len))) {
    fprintf(stderr, "Error: invalid manager key %s.\n", s_mgrkey);
    return IERROR;
  }
  mem_free(b_mgrkey); b_mgrkey = NULL;  

  /* Parse filename for blinding key */
  s_bldkey = argv[argnum];
  argnum++;
  
  /* Import the blinding key */
  b_bldkey = NULL;
  if(misc_read_file_to_bytestring(s_bldkey, &b_bldkey, &b_len) == IERROR) {
    fprintf(stderr, "Error: failed to import blinding key.\n");
    return IERROR;
  }
    
  if(!(bldkey = groupsig_bld_key_import(scheme, b_bldkey, (uint32_t) b_len))) {
    fprintf(stderr, "Error: invalid blinding key %s.\n", s_bldkey);
    return IERROR;
  }
  mem_free(b_bldkey); b_bldkey = NULL;

  /* Load group signatures and messages, and blind them */
  n_sigs = argc - argnum;
  sig1 = argnum;
  bsigs = (groupsig_blindsig_t **) mem_malloc(sizeof(groupsig_blindsig_t *)*n_sigs);
  csigs = (groupsig_blindsig_t **) mem_malloc(sizeof(groupsig_blindsig_t *)*n_sigs);  

  for(i=argnum;i<argnum+n_sigs; i++) {

    /* Import i-th blinded signature */
   b_bsig = NULL;
    if(misc_read_file_to_bytestring(argv[i], &b_bsig, &b_len) == IERROR) {
      fprintf(stderr, "Error: failed to import blinded signature from %s.\n", argv[i]);
      return IERROR;
    }
    
    if(!(bsigs[i-argnum] = groupsig_blindsig_import(scheme, b_bsig, (uint32_t) b_len))) {
      fprintf(stderr, "Error: failed to import blinded signature.\n");
      return IERROR;
    }
    mem_free(b_bsig); b_bsig = NULL;

    /* Initialize the i-th converted signature */
    if(!(csigs[i-argnum] = groupsig_blindsig_init(scheme))) {
      fprintf(stderr, "Error: failed to initialize converted signature.\n");
      return IERROR;
    }
    
  }
  
  /* Convert signatures and messages */
  if(groupsig_convert(csigs, bsigs, n_sigs, grpkey, mgrkey, bldkey, NULL) ==
     IERROR) {
    fprintf(stderr, "Error: failed to convert signatures.\n");
    return IERROR;
  }

  for(i=sig1;i<sig1+n_sigs; i++) {

    /* Export the converted signatures */
    // @todo fixed to +5 char filename
    if(!(s_csig = (char *) mem_malloc(sizeof(char)*(strlen(argv[i])+5)))) {
      return IERROR;
    }
    
    sprintf(s_csig, "%s.cnv", argv[i]);

    b_bsig = NULL;
    if(groupsig_blindsig_export(&b_bsig, (uint32_t *) &b_len, csigs[i-sig1]) == IERROR) {
      return IERROR;
    }

    if(misc_bytes_to_file(s_csig, b_bsig, b_len) == IERROR) {
      fprintf(stderr, "Error: Could not export converted signature to %s.\n", s_csig);
      return IERROR;
    }
    mem_free(b_bsig); b_bsig = NULL;     
    mem_free(s_csig); s_csig = NULL;
      
  }  

  /* Free resources */
  for(i=0; i<n_sigs; i++) {
    groupsig_blindsig_free(bsigs[i]); bsigs[i] = NULL;
    groupsig_blindsig_free(csigs[i]); csigs[i] = NULL;
  }
  mem_free(bsigs); bsigs = NULL;
  mem_free(csigs); csigs = NULL;

  groupsig_clear(scheme);
  if(bldkey) { groupsig_bld_key_free(bldkey); bldkey = NULL; }
  if(grpkey) { groupsig_grp_key_free(grpkey); grpkey = NULL; }
  if(mgrkey) { groupsig_mgr_key_free(mgrkey); mgrkey = NULL; }
  
  return IOK;
  
}

/* revoke.c ends here */
