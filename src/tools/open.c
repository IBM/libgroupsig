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
#include "logger.h"
#include "misc/misc.h"
#include "sys/mem.h"

#ifdef PROFILE
#include "misc/profile.h"
#endif

log_t logger;
sysenv_t *sysenv;

int main(int argc, char *argv[]) {

  int argnum = 1; // Next argument to process
  char *s_sig, *s_grpkey, *s_mgrkey, *s_gml, *s_crl;
  groupsig_key_t *grpkey, *mgrkey;
  gml_t *gml;
  crl_t *crl;
  groupsig_signature_t *sig;
  byte_t *b_grpkey, *b_mgrkey, *b_sig, *b_gml;
#ifdef PROFILE
  profile_t *prof_open, *prof_reveal;
  struct timeval tv_begin, tv_end;
  uint64_t n, iter, uint64;
  clock_t clck_begin, clck_end;
  uint64_t cycle_begin, cycle_end;
  uint8_t profile_skip;
  char *s_sig_i;
#endif
  uint64_t b_len, index;
  uint32_t gml_len;
  int rc;
  uint8_t scheme;

  if(argc == 1) {
    fprintf(stdout, "Usage: %s <scheme> <sig> <grp_key> <mgr_key> <GML>\n",
	    basename(argv[0]));
    return IOK;
  }

  if((groupsig_get_code_from_str(&scheme, argv[argnum])) == IERROR) {
    fprintf(stderr, "Error: Wrong scheme %s\n", argv[argnum]);
    return IERROR;
  }
  argnum++;

  if(groupsig_init(scheme, time(NULL)) == IERROR) {
    return IERROR;
  }

  s_sig = argv[argnum];
  argnum++;

  s_grpkey = argv[argnum];
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

  /* Import the manager key */
  b_mgrkey = NULL;
  if(misc_read_file_to_bytestring(s_mgrkey, &b_mgrkey, &b_len) == IERROR) {
    fprintf(stderr, "Error: failed to read manager key.\n");
    return IERROR;
  }
  
  if(!(mgrkey = groupsig_mgr_key_import(scheme, b_mgrkey, b_len))) {
    fprintf(stderr, "Error: invalid manager key %s.\n", s_mgrkey);
    return IERROR;
  }
  mem_free(b_mgrkey); b_mgrkey = NULL; 

  /* Import the GML */
  b_gml = NULL;
  if(misc_read_file_to_bytestring(s_gml, &b_gml, (uint64_t *) &gml_len) == IERROR) {
    fprintf(stderr, "Error: Could not read GML file %s\n", s_gml);
    return IERROR;
  }
  
  /* Import the GML from the bytes */
  if(!(gml = gml_import(scheme, b_gml, gml_len))) {
    fprintf(stderr, "Error: invalid GML %s.\n", s_gml);
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

    /* Import the signature */
    b_sig = NULL;
    if(misc_read_file_to_bytestring(s_sig_i, &b_sig, (uint64_t *) &b_len) == IERROR) {
      fprintf(stderr, "Error: failed to import signature from %s.\n", s_sig_i);
      return IERROR;
    }
    
    if(!(sig = groupsig_signature_import(scheme, b_sig, b_len))) {
      fprintf(stderr, "Error: failed to import signature.\n");
      return IERROR;
    }
    mem_free(b_sig); b_sig = NULL;
#else

    /* Import the signature */
    b_sig = NULL;
    if(misc_read_file_to_bytestring(s_sig, &b_sig, (uint64_t *) &b_len) == IERROR) {
      fprintf(stderr, "Error: failed to import signature from %s.\n", s_sig);
      return IERROR;
    }
    
    if(!(sig = groupsig_signature_import(scheme, b_sig, b_len))) {
      fprintf(stderr, "Error: failed to import signature.\n");
      return IERROR;
    }
    mem_free(b_sig); b_sig = NULL;
    
#endif
  
#ifdef PROFILE
    if(profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR) {
      profile_skip = 1;
    } else {
      profile_skip = 0;
    }
#endif

    if((rc = groupsig_open(&index, NULL, NULL, sig, grpkey, mgrkey, gml)) == IERROR) {
      fprintf(stderr, "Error opening signature.\n");
      return IERROR;
    }

#ifdef PROFILE
    if(!profile_skip && profile_get_time(&tv_end, &clck_end, &cycle_end) == IOK) {
      profile_dump_entry(prof_open, &tv_begin, &tv_end, clck_begin, clck_end, cycle_begin, cycle_end);
    }
#endif

    if(rc == IFAIL) {
      fprintf(stderr, "Unable to open signature %s: no suitable entry found.\n", s_sig);
      return IERROR;
    }

#ifdef PROFILE
    if(profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR) {
      profile_skip = 1;
    } else {
      profile_skip = 0;
    }
#endif

    fprintf(stdout, "Signer: %lu\n", index);
    
#ifdef PROFILE
    if(!profile_skip && profile_get_time(&tv_end, &clck_end, &cycle_end) == IOK) {
      profile_dump_entry(prof_reveal, &tv_begin, &tv_end, clck_begin, clck_end, cycle_begin, cycle_end);
    }

    groupsig_signature_free(sig); sig = NULL;
    free(s_sig_i); s_sig_i = NULL;

  }

#endif

  if(sig) { groupsig_signature_free(sig); sig = NULL; }

  groupsig_clear(scheme);
  groupsig_mgr_key_free(mgrkey); mgrkey = NULL;
  groupsig_grp_key_free(grpkey); grpkey = NULL;
  gml_free(gml); gml = NULL;

#ifdef PROFILE
  profile_free(prof_open); prof_open = NULL;
  profile_free(prof_reveal); prof_reveal = NULL;
#endif
      
  return IOK;
  
}

/* open.c ends here */
