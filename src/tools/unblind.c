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
  char *s_proof, *s_bldkey, *s_bsig, *s_nym, *s_msg;
  groupsig_blindsig_t **bsigs;
  groupsig_key_t *bldkey;
  identity_t *nym;
  message_t *msg;
  byte_t *b_bldkey, *b_sig;
  int key_format, sig_format, proof_format, i, n_sigs;
  uint64_t b_len;
  uint8_t scheme;

  if(argc == 1) {
    fprintf(stdout, "Usage: %s <IN: scheme> <IN: blinding key> "
	    "<IN: cnv sig1> ... <IN: cnv sign>\n",
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
  bsigs = (groupsig_blindsig_t **) mem_malloc(sizeof(groupsig_blindsig_t *)*n_sigs);

  for(i=argnum;i<argnum+n_sigs; i++) {

    if(!(nym = identity_init(scheme))) {
      fprintf(stderr, "Error: failed to initialize identity.\n");
      return IERROR;
    }

    if(!(msg = message_init())) {
      fprintf(stderr, "Error: failed to initialize message.\n");
      return IERROR;
    }

    /* Import i-th signature */
    b_sig = NULL;
    if(misc_read_file_to_bytestring(argv[i], &b_sig, &b_len) == IERROR) {
      fprintf(stderr, "Error: failed to import blinded signature key.\n");
      return IERROR;
    }
    
    if(!(bsigs[i-argnum] = groupsig_blindsig_import(scheme, b_sig, b_len))) {
      fprintf(stderr, "Error: failed to import blinded signature %s.\n", argv[i]);
      return IERROR;
    }
    mem_free(b_sig); b_sig = NULL;

    /* Unblind the signature and message */
    if(groupsig_unblind(nym, NULL, bsigs[i-argnum], NULL, bldkey, msg) == IERROR) {
      fprintf(stderr, "Error: failed to unblind signature.\n");
      return IERROR;
    }

    /* Print the converted identity and associated message */
    if(!(s_nym = identity_to_string(nym))) {
      fprintf(stderr, "Error: failed to stringify nym.\n");
      return IERROR;
    }

    if(!(s_msg = message_to_string(msg))) {
      fprintf(stderr, "Error: failed to stringify message.\n");
      return IERROR;
    }
    
    fprintf(stdout, "Unblinded nym and message: %d\n\tnym: %s\n\tmsg: %s\n",
    	    i-argnum, s_nym, s_msg);
    
    if (nym) { identity_free(nym); nym = NULL; }
    if (msg) { message_free(msg); msg = NULL; }
    if (s_nym) { mem_free(s_nym); s_nym = NULL; }
    if (s_msg) { mem_free(s_msg); s_msg = NULL; }
    
  }

  /* Free resources */
  for(i=0; i<n_sigs; i++) {
    groupsig_blindsig_free(bsigs[i]); bsigs[i] = NULL;
  }
  mem_free(bsigs); bsigs = NULL;

  groupsig_clear(scheme);
  if (bldkey) { groupsig_bld_key_free(bldkey); bldkey = NULL; }
  
  return IOK;
  
}

/* revoke.c ends here */
