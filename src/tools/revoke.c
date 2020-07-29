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

#ifdef PROFILE
#include "misc/profile.h"
#endif

log_t logger;
sysenv_t *sysenv;

int main(int argc, char *argv[]) {

  int argnum = 1; // Next argument to process
  char *s_sig, *s_grpkey, *s_mgrkey, *s_gml, *s_crl;
  groupsig_config_t *cfg;  
  groupsig_key_t *grpkey, *mgrkey;
  gml_t *gml;
  crl_t *crl;
  groupsig_signature_t *sig;
  identity_t *id;
  trapdoor_t *trap;
#ifdef PROFILE
  profile_t *prof_open, *prof_reveal;
  struct timeval tv_begin, tv_end;
  uint64_t n, iter, uint64;
  clock_t clck_begin, clck_end;
  uint64_t cycle_begin, cycle_end;
  uint8_t profile_skip;
  char *s_sig_i;
#endif
  int key_format, sig_format, rc;
  uint8_t scheme;

  if(argc == 1) {
    fprintf(stdout, "Usage: %s <scheme> <file format> <sig> <grp_key> <mgr_key> <GML> <CRL>\n",
	    basename(argv[0]));
    return IOK;
  }

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
  }
  else if(strcmp(argv[argnum], "b64") == 0){
    key_format = EXIM_FORMAT_FILE_NULL_B64;
    sig_format = EXIM_FORMAT_FILE_NULL_B64;
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
  } else if (scheme == GROUPSIG_BBS04_CODE ||
	     scheme == GROUPSIG_CPY06_CODE) {
    key_format = EXIM_FORMAT_FILE_NULL;
    sig_format = EXIM_FORMAT_FILE_NULL;
  }*/

  s_sig = argv[argnum];
  argnum++;

  s_grpkey = argv[argnum];
  argnum++;

  s_mgrkey = argv[argnum];
  argnum++;

  s_gml = argv[argnum];
  argnum++;

  s_crl = argv[argnum];
  argnum++;

#ifdef PROFILE      
  errno = 0;
  uint64 = strtoul(argv[argnum], NULL, 10);
  argnum++;
  if(errno) {
    fprintf(stderr, "Error: %s\n", strerror(errno));
    return IERROR;
  }
  n = uint64;
#endif

  if(!(grpkey = groupsig_grp_key_import(scheme, key_format, s_grpkey))) {
    fprintf(stderr, "Error: invalid group key %s.\n", s_grpkey);
    return IERROR;
  }

  if(!(mgrkey = groupsig_mgr_key_import(scheme, key_format, s_mgrkey))) {
    fprintf(stderr, "Error: invalid manager key %s.\n", s_mgrkey);
    return IERROR;
  }

  if(!(gml = gml_import(scheme, GML_FILE, s_gml))) {
    fprintf(stderr, "Error: invalid GML %s.\n", s_gml);
    return IERROR;
  }

  if(!(crl = crl_import(scheme, CRL_FILE, s_crl))) {
    fprintf(stderr, "Error: invalid CRL %s.\n", s_crl);
    return IERROR;
  }

#ifdef PROFILE
  if(!(prof_open = profile_begin("open.prf"))) {
    return IERROR;
  }

  if(!(prof_reveal = profile_begin("reveal.prf"))) {
    return IERROR;
  }

  for(iter=0; iter<n; iter++) {

    // @todo fixed to 10 char filename (without extension)
    if(!(s_sig_i = (char *) malloc(sizeof(char)*(strlen(s_sig)+10)))) {
      return IERROR;
    }

    sprintf(s_sig_i, "%s_%d", s_sig, iter);

    if(!(sig = groupsig_signature_import(scheme, sig_format, s_sig_i))) {
      fprintf(stderr, "Error: invalid group signature %s\n", s_sig_i);
      return IERROR;
    }
#else

    if(!(sig = groupsig_signature_import(scheme, sig_format, s_sig))) {
      fprintf(stderr, "Error: invalid group signature %s\n", s_sig);
      return IERROR;
    }
#endif

    if(!(id = identity_init(scheme))) {
      fprintf(stderr, "Error creating identity.\n");
      return IERROR;
    }
  
#ifdef PROFILE
    if(profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR) {
      profile_skip = 1;
    } else {
      profile_skip = 0;
    }
#endif

    /* We do not use proofs of opening nor "anonymity CRL" */
    if((rc = groupsig_open(id, NULL, NULL, sig, grpkey, mgrkey, gml)) == IERROR) {
      fprintf(stderr, "Error opening signature.\n");
      return IERROR;
    }

#ifdef PROFILE
    if(!profile_skip && profile_get_time(&tv_end, &clck_end, &cycle_end) == IOK) {
      profile_dump_entry(prof_open, &tv_begin, &tv_end, clck_begin, clck_end, cycle_begin, cycle_end);
    }
#endif

    if(rc == IFAIL) {
      fprintf(stderr, "Unable to open signature %s: no suitable trapdoor found.\n", s_sig);
      return IERROR;
    }

    if(!(trap = trapdoor_init(scheme))) {
      fprintf(stderr, "Error creating trapdoor.\n");
      return IERROR;
    }

#ifdef PROFILE
    if(profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR) {
      profile_skip = 1;
    } else {
      profile_skip = 0;
    }
#endif
    
    /* Reveal the tracing trapdoor */
    if(groupsig_reveal(trap, crl, gml, *(uint64_t *) id->id) == IERROR) {
      fprintf(stderr, "Error in reveal.\n");
      return IERROR;
    }

#ifdef PROFILE
    if(!profile_skip && profile_get_time(&tv_end, &clck_end, &cycle_end) == IOK) {
      profile_dump_entry(prof_reveal, &tv_begin, &tv_end, clck_begin, clck_end, cycle_begin, cycle_end);
    }

    groupsig_signature_free(sig); sig = NULL;
    /* identity_free(id); id = NULL; */
    /* trapdoor_free(trap); trap = NULL; */
    free(s_sig_i); s_sig_i = NULL;

  }

#endif

  /* Export the CRL to save the changes */
  if(crl_export(crl, s_crl, CRL_FILE) == IERROR) {
    fprintf(stderr, "Error exporting CRL.\n");
    return IERROR;
  }

  if(sig) { groupsig_signature_free(sig); sig = NULL; }
  identity_free(id); id = NULL;
  trapdoor_free(trap); trap = NULL;

  groupsig_clear(scheme, cfg); cfg = NULL;
  groupsig_mgr_key_free(mgrkey); mgrkey = NULL;
  groupsig_grp_key_free(grpkey); grpkey = NULL;
  /* gml_free(gml); gml = NULL; */
  /* crl_free(crl); crl = NULL; */

#ifdef PROFILE
  profile_free(prof_open); prof_open = NULL;
  profile_free(prof_reveal); prof_reveal = NULL;
#endif
      
  return IOK;
  
}

/* revoke.c ends here */
