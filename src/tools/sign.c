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
#include "logger.h"

#include "message.h"
#include "misc/misc.h"
#include "sys/mem.h"

#ifdef PROFILE
#include "misc/profile.h"
#endif

log_t logger;
sysenv_t *sysenv;

int main(int argc, char *argv[]) {
  int argnum = 1; // Next argument to process
  char *s_sig, *s_msg, *s_grpkey, *s_memkey;
  groupsig_key_t *grpkey, *memkey;
  groupsig_signature_t *sig;
  message_t *msg;
  byte_t *b_grpkey, *b_memkey, *b_sig, *b_msg;
  uint64_t msg_len;
#ifdef PROFILE
  profile_t *prof;
  char *s_sig_i;
  struct timeval tv_begin, tv_end;
  uint64_t n, i, uint64;
  clock_t clck_begin, clck_end;
  uint64_t cycle_begin, cycle_end;
  uint8_t profile_skip;
#endif
  uint32_t b_len;
  int key_format, sig_format;
  uint8_t scheme;

  if(argc == 1) {
    fprintf(stdout, "Usage: %s <scheme> <signature file> <msg file> <member key> <group key>\n",
	    basename(argv[0]));
    return IOK;
  }

  /* Initialize the group signature environment */
  if((groupsig_get_code_from_str(&scheme, argv[argnum])) == IERROR) {
    fprintf(stderr, "Error: Wrong scheme %s\n", argv[argnum]);
    return IERROR;
  } 
  argnum++;


  if(groupsig_init(scheme, 0) == IERROR) {
    return IERROR;
  }

  s_sig = argv[argnum];
  argnum++;

  s_msg = argv[argnum];
  argnum++;

  s_memkey = argv[argnum];
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

  /* Initialize the message object */
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

#ifdef PROFILE
  if(!(prof = profile_begin("sign.prf"))) {
    return IERROR;
  }
  
  for(i=0; i<n; i++) {
#endif

  /* Initialize the group signature object */
  if(!(sig = groupsig_signature_init(scheme))) {
    fprintf(stderr, "Error: failed to initialize the group signature object.\n");
    return IERROR;
  }

  /* Import the member key */
  b_memkey = NULL;
  if(misc_read_file_to_bytestring(s_memkey, &b_memkey, (uint64_t *) &b_len) == IERROR) {
    fprintf(stderr, "Error: failed to import member key.\n");
    return IERROR;
  }
  
  if(!(memkey = groupsig_mem_key_import(scheme, b_memkey, b_len))) {
    fprintf(stderr, "Error: invalid member key %s.\n", s_memkey);
    return IERROR;
  }
  mem_free(b_memkey); b_memkey = NULL;
  

#ifdef PROFILE
    if(profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR) {
      profile_skip = 1;
    } else {
      profile_skip = 0;
    }
#endif

  /* Sign the message: setting the seed to UINT_MAX forces to get a new pseudo
     random number for this signature instead of using a pre-fixed random number. */
  if(groupsig_sign(sig, msg, memkey, grpkey, UINT_MAX) == IERROR) {
    fprintf(stderr, "Error: signing failure.\n");
    return IERROR;
  }

#ifdef PROFILE
    if(!profile_skip && profile_get_time(&tv_end, &clck_end, &cycle_end) == IOK) {
      profile_dump_entry(prof, &tv_begin, &tv_end, clck_begin, clck_end, cycle_begin, cycle_end);
    }

    // @todo fixed to 10 char filename (without extension)
    if(!(s_sig_i = (char *) malloc(sizeof(char)*(strlen(s_sig)+10)))) {
      return IERROR;
    }

    sprintf(s_sig_i, "%s_%d", s_sig, i);

    /* Export the signature to the specified file */
    if(groupsig_signature_export(sig, sig_format, s_sig_i) == IERROR) {
      fprintf(stderr, "Error: failed to export the group signature.\n");
      return IERROR;
    }

    free(s_sig_i); s_sig_i = NULL;
    groupsig_signature_free(sig); sig = NULL;
    groupsig_mem_key_free(memkey); memkey = NULL;

  }

#else

  /* Export the signature to the specified file */
  b_sig = NULL;
  if(groupsig_signature_export(&b_sig, &b_len, sig) == IERROR) {
    fprintf(stderr, "Error: failed to export the group signature.\n");
    return IERROR;
  }

  if(misc_bytes_to_file(s_sig, b_sig, b_len) == IERROR) {
    fprintf(stderr, "Error: Could not export signature to %s.\n", s_sig);
    return IERROR;
  }
  mem_free(b_sig); b_sig = NULL;

#endif
  
  /* Free resources */
  groupsig_clear(scheme);
  if(sig) { groupsig_signature_free(sig); sig = NULL; }
  if(grpkey) { groupsig_grp_key_free(grpkey); grpkey = NULL; }
  if(memkey) { groupsig_mem_key_free(memkey); memkey = NULL; }
  message_free(msg); msg = NULL;  

#ifdef PROFILE
  profile_free(prof); prof = NULL;
#endif
  
  return IOK;
  
}

/* sign.c ends here */
