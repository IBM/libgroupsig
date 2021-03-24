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

#include "misc/misc.h"
#include "sys/mem.h"

#ifdef PROFILE
#include "misc/profile.h"
#endif

log_t logger;
sysenv_t *sysenv;

int main(int argc, char *argv[]) {
  int argnum = 1;
  char *s_sig, *s_msg, *s_grpkey;
  groupsig_key_t *grpkey;
  groupsig_signature_t *sig;
  message_t *msg;
  byte_t *b_grpkey, *b_sig, *b_msg;
  uint64_t msg_len;
#ifdef PROFILE
  profile_t *prof;
  uint64_t n, i, uint64;
  struct timeval tv_begin, tv_end;
  clock_t clck_begin, clck_end;
  uint64_t cycle_begin, cycle_end;
  uint8_t profile_skip;
  char *s_sig_i;
#endif
  uint32_t b_len;
  int key_format, sig_format;
  uint8_t b, scheme;

  if(argc == 1) {
    fprintf(stdout, "Usage: %s <scheme> <signature file> <msg file> <group key>\n",
	    basename(argv[0]));
    return IOK;
  }

  /* Initialize the group signature environment */
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

  s_msg = argv[argnum];
  argnum++;

  s_grpkey = argv[argnum];
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
    fprintf(stderr, "Error: failed to import member key.\n");
    return IERROR;
  }
  
  if(!(grpkey = groupsig_grp_key_import(scheme, b_grpkey, b_len))) {
    fprintf(stderr, "Error: invalid group key %s.\n", s_grpkey);
    return IERROR;
  }
  mem_free(b_grpkey); b_grpkey = NULL;

#ifdef PROFILE
  if(!(prof = profile_begin("verify.prf"))) {
    return IERROR;
  }
  
  for(i=0; i<n; i++) {

    // @todo fixed to 10 char filename (without extension)
    if(!(s_sig_i = (char *) malloc(sizeof(char)*(strlen(s_sig)+10)))) {
      return IERROR;
    }

    sprintf(s_sig_i, "%s_%d", s_sig, i);

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
      fprintf(stderr, "Error: failed to read signature from %s.\n", s_sig);
      return IERROR;
    }
    
    if(!(sig = groupsig_signature_import(scheme, b_sig, b_len))) {
      fprintf(stderr, "Error: failed to import signature.\n");
      return IERROR;
    }
    mem_free(b_sig); b_sig = NULL;
#endif

    /* Initialize message */
    b_msg = NULL;
    if (misc_read_file_to_bytestring(s_msg, &b_msg, &msg_len) == IERROR) {
      fprintf(stderr, "Error: failed to read message file %s\n", s_msg);
      return IERROR;
    }
    
    if (!(msg = message_from_bytes(b_msg, msg_len))) {
      fprintf(stderr, "Error: failed to import message from file %s\n",
	      s_msg);
      return IERROR;      
    }
    
    mem_free(b_msg); b_msg = NULL;
    mem_free(b_sig); b_sig = NULL;

#ifdef PROFILE
    if(profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR) {
      profile_skip = 1;
    } else {
      profile_skip = 0;
    }
#endif

    if(groupsig_verify(&b, sig, msg, grpkey) == IERROR) {
      fprintf(stderr, "Error: verification failure.\n");
      return IERROR;
    }

#ifdef PROFILE
    if(!profile_skip && profile_get_time(&tv_end, &clck_end, &cycle_end) == IOK) {
      profile_dump_entry(prof, &tv_begin, &tv_end, clck_begin, clck_end, cycle_begin, cycle_end);
    }
#endif

    if(!b) {
      fprintf(stdout, "WRONG signature.\n");
      return IERROR;
    } else {
      fprintf(stdout, "VALID signature.\n");
    }
  
    /* Free resources */
    groupsig_signature_free(sig); sig = NULL;

#ifdef PROFILE
  }
#endif

  groupsig_clear(scheme);
  groupsig_grp_key_free(grpkey); grpkey = NULL;
  message_free(msg); msg = NULL;  
  
  return IOK;
  
}

/* verify.c ends here */
