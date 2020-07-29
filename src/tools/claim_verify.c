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
#include "logger.h"

#include "sys/mem.h"

#ifdef PROFILE
#include "misc/profile.h"
#endif

log_t logger;
sysenv_t *sysenv;

int main(int argc, char *argv[]) {

  int argnum = 1; // Next argument to process
  char *s_proof, *s_grpkey;
  groupsig_config_t *cfg;  
  groupsig_key_t *grpkey;
  groupsig_proof_t *proof;
  groupsig_signature_t **sigs;
#ifdef PROFILE
  profile_t *prof;
  char *s_sig_i, *s_proof_i;
  struct timeval tv_begin, tv_end;
  uint64_t n, iter, uint64;
  clock_t clck_begin, clck_end;
  uint64_t cycle_begin, cycle_end;
  uint8_t profile_skip;
#endif
  int key_format, sig_format, proof_format, i, n_sigs;
  uint8_t bool, scheme;

  if(argc == 1) {
    fprintf(stdout, "Usage: %s <scheme> <file format> <proof> <group key> <sig1> ... <sign>\n",
	    basename(argv[0]));
    return IOK;
  }

  /* Initialize the group signature environment */
  if((groupsig_get_code_from_str(&scheme, argv[argnum])) == IERROR) {
    fprintf(stderr, "Error: Wrong scheme %s\n", argv[argnum]);
    return IERROR;
  }
  argnum++;

  if(!(cfg = groupsig_init(scheme, time(NULL)))) {
    return IERROR;
  }
  
  if(strcmp(argv[argnum], "bin") == 0){
    key_format = EXIM_FORMAT_FILE_NULL;
    sig_format = EXIM_FORMAT_FILE_NULL;
    proof_format = EXIM_FORMAT_FILE_NULL;
  }
  else if(strcmp(argv[argnum], "b64") == 0){
    key_format = EXIM_FORMAT_FILE_NULL_B64;
    sig_format = EXIM_FORMAT_FILE_NULL_B64;
    proof_format = EXIM_FORMAT_FILE_NULL_B64;
  }
  else {
    fprintf(stderr, "Error: Invalid format %s\n", argv[1]);
    return IERROR;
  }
  argnum++;
  /* @todo fixed key formats! */
  /*if(scheme == GROUPSIG_KTY04_CODE) {
    key_format = EXIM_FORMAT_FILE_NULL_B64;
    sig_format = EXIM_FORMAT_FILE_NULL_B64;
    proof_format = EXIM_FORMAT_FILE_NULL_B64;
  } else if (scheme == GROUPSIG_BBS04_CODE ||
	     scheme == GROUPSIG_CPY06_CODE) {
    key_format = EXIM_FORMAT_FILE_NULL;
    sig_format = EXIM_FORMAT_FILE_NULL;
    proof_format = EXIM_FORMAT_FILE_NULL;
  }*/

  s_proof = argv[argnum];
  argnum++;

  s_grpkey = argv[argnum];
  argnum++;


#ifdef PROFILE
  errno = 0;
  uint64 = strtoul(argv[argc-1], NULL, 10);
  argnum++;
  if(errno) {
    fprintf(stderr, "Error: %s\n", strerror(errno));
    return IERROR;
  }
  n = uint64;
#endif

  /* Import the group key */
  if(!(grpkey = groupsig_grp_key_import(scheme, key_format, s_grpkey))) {
    fprintf(stderr, "Error: invalid group key %s.\n", s_grpkey);
    return IERROR;
  }

#ifdef PROFILE
  if(!(prof = profile_begin("claim_verify.prf"))) {
    return IERROR;
  }
  
  for(iter=0; iter<n; iter++) {
    
    /* @todo Profiling just supports claims over 1 group sig... */
    // @todo fixed to 10 char filename (without extension)
    if(!(s_sig_i = (char *) malloc(sizeof(char)*(strlen(argv[argc-2])+10)))) {
      return IERROR;
    }

    sprintf(s_sig_i, "%s_%d", argv[argc-2], iter);

    n_sigs = 1;
    sigs = (groupsig_signature_t **) mem_malloc(sizeof(groupsig_signature_t *));
    if(!(sigs[0] = groupsig_signature_import(scheme, sig_format, s_sig_i))) {
      fprintf(stderr, "Error: failed to import signature %s.\n", s_sig_i);
      return IERROR;
    }

    // @todo fixed to 10 char filename (without extension)
    if(!(s_proof_i = (char *) malloc(sizeof(char)*(strlen(s_proof)+10)))) {
      return IERROR;
    }

    sprintf(s_proof_i, "%s_%d", s_proof, iter);

    /* Import the proof */
    if(!(proof = groupsig_proof_import(scheme, proof_format, s_proof_i))) {
      fprintf(stderr, "Error: failed to import proof.\n");
      return IERROR;
    }

#else
    n_sigs = argc - argnum;
    sigs = (groupsig_signature_t **) mem_malloc(sizeof(groupsig_signature_t *)*n_sigs);
    for(i=argnum; i<argc; i++) {
      if(!(sigs[i-argnum] = groupsig_signature_import(scheme, sig_format, argv[i]))) {
	fprintf(stderr, "Error: failed to import signature %s.\n", argv[i]);
	return IERROR;
      }
    }
  
    /* Import the proof */
    if(!(proof = groupsig_proof_import(scheme, proof_format, s_proof))) {
      fprintf(stderr, "Error: failed to import proof.\n");
      return IERROR;
    }

#endif

#ifdef PROFILE
    if(profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR) {
      profile_skip = 1;
    } else {
      profile_skip = 0;
    }
#endif

    /* Verify the proof */
    if(groupsig_prove_equality_verify(&bool, proof, grpkey, sigs, n_sigs) == IERROR) {
      fprintf(stderr, "Error: proof verification failure.\n");
      return IERROR;
    }

#ifdef PROFILE
    if(!profile_skip && profile_get_time(&tv_end, &clck_end, &cycle_end) == IOK) {
      profile_dump_entry(prof, &tv_begin, &tv_end, clck_begin, clck_end, cycle_begin, cycle_end);
    }
#endif

    if(!bool) {
      fprintf(stdout, "WRONG proof.\n");
    } else {
      fprintf(stdout, "VALID proof.\n");
    }

#ifdef PROFILE
    groupsig_signature_free(sigs[0]); sigs[0] = NULL;
    groupsig_proof_free(proof); proof = NULL;    
    
  }

#endif  
  /* Free resources */
  for(i=0; i<argc-5; i++) {
    groupsig_signature_free(sigs[i]); sigs[i] = NULL;
  }
  free(sigs); sigs = NULL;
  groupsig_clear(scheme, cfg); cfg = NULL;
  groupsig_proof_free(proof); proof = NULL;
  groupsig_grp_key_free(grpkey); grpkey = NULL;
  
  return IOK;
  
}

/* revoke.c ends here */
