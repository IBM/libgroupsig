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
#include "logger.h"
#include "message.h"


#ifdef PROFILE
#include "misc/profile.h"
#endif

log_t logger;
sysenv_t *sysenv;

int main(int argc, char *argv[]) {

  int argnum = 1; // Next argument to process
  char *s_sig, *s_grpkey, *s_crl, *s_mgrkey, *s_gml;
  groupsig_config_t *cfg;    
  groupsig_key_t *grpkey, *mgrkey;
  crl_t *crl;
  gml_t *gml;
  groupsig_signature_t *sig;
#ifdef PROFILE
  profile_t *prof;
  struct timeval tv_begin, tv_end;
  uint64_t n, iter, uint64;
  clock_t clck_begin, clck_end;
  uint64_t cycle_begin, cycle_end;
  uint8_t profile_skip;
  char *s_sig_i;
#endif
  int key_format, sig_format;
  uint8_t revoked, scheme;

  if(argc == 1) {
    fprintf(stdout, "Usage: %s <scheme> <file format> <sig> <grp_key> <CRL> <mgr_key> <GML>\n",
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

  s_crl = argv[argnum];
  argnum++;

  s_mgrkey = argv[argnum];
  argnum++;

  s_gml = argv[argnum];
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

  /* Import the group key */
  if(!(grpkey = groupsig_grp_key_import(scheme, key_format, s_grpkey))) {
    fprintf(stderr, "Error: invalid group key %s.\n", s_grpkey);
    return IERROR;
  }

  /* Import the CRL */
  if(!(crl = crl_import(scheme, CRL_FILE, s_crl))) {
    fprintf(stderr, "Error: invalid CRL %s.\n", s_crl);
    return IERROR;
  }

  /* Import the manager key */
  if(!(mgrkey = groupsig_mgr_key_import(scheme, key_format, s_mgrkey))) {
    fprintf(stderr, "Error: invalid manager key %s.\n", s_mgrkey);
    return IERROR;
  }
  
  /* Import the GML */
  if(!(gml = gml_import(scheme, GML_FILE, s_gml))) {
    fprintf(stderr, "Error: invalid GML %s.\n", s_gml);
    return IERROR;
  }

#ifdef PROFILE
  if(!(prof = profile_begin("trace.prf"))) {
    return IERROR;
  }

  for(iter=0; iter<n; iter++) {

    // @todo fixed to 10 char filename (without extension)
    if(!(s_sig_i = (char *) malloc(sizeof(char)*(strlen(s_sig)+10)))) {
      return IERROR;
    }

    sprintf(s_sig_i, "%s_%d", s_sig, iter);

    /* Import the signature */
    if(!(sig = groupsig_signature_import(scheme, sig_format, s_sig_i))) {
      fprintf(stderr, "Error: invalid group signature %s\n", s_sig_i);
      return IERROR;
    }
#else

    /* Import the signature */
    if(!(sig = groupsig_signature_import(scheme, sig_format, s_sig))) {
      fprintf(stderr, "Error: invalid group signature %s\n", s_sig);
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
  
    revoked = 0;
    if(groupsig_trace(&revoked, sig, grpkey, crl, mgrkey, gml) == IERROR) {
      fprintf(stderr, "Error: failed to trace the signature.\n");
      return IERROR;
    }

#ifdef PROFILE
    if(!profile_skip && profile_get_time(&tv_end, &clck_end, &cycle_end) == IOK) {
      profile_dump_entry(prof, &tv_begin, &tv_end, clck_begin, clck_end, cycle_begin, cycle_end);
    }
#endif

    if(!revoked) {
      fprintf(stdout, "VALID signer.\n");
    } else {
      fprintf(stdout, "REVOKED signer.\n");
    }
  
    groupsig_signature_free(sig); sig = NULL;

#ifdef PROFILE
  }

  profile_free(prof); prof = NULL;
#endif

  groupsig_clear(scheme, cfg); cfg = NULL;
  groupsig_grp_key_free(grpkey); grpkey = NULL;
  crl_free(crl); crl = NULL;
  
  return IOK;
  
}

/* revoke.c ends here */
