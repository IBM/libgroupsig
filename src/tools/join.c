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
#include <stdint.h>
#include <time.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>        
#include <sys/stat.h>
#include <stdarg.h>
#include <libgen.h>

#include "groupsig.h"
#include "gml.h"
/* #include "kty04.h" */
#include "types.h"
#include "sysenv.h"
#include "logger.h"

#include "sys/mem.h"
#include "misc/misc.h"

#ifdef PROFILE
#include "misc/profile.h"
#endif

log_t logger;
sysenv_t *sysenv;

static char* _keyfile_name(char *dirfile, uint64_t index) {

  char *s, *sindex;

  if(!dirfile) {
    fprintf(stderr, "Error: %s\n", strerror(EINVAL));
    return NULL;
  }

  if(!(sindex = misc_uint642string(index))) {
    return NULL;
  }

  if(!(s = (char *) mem_malloc(sizeof(char)*
			       (strlen(dirfile)+strlen(sindex)+strlen(".key")+2)))) {
    mem_free(sindex); sindex = NULL;
    return NULL;
  }

  sprintf(s, "%s/%s.key", dirfile, sindex);

  mem_free(sindex); sindex = NULL;

  return s;

}

/* @todo: Error management and memory cleanup. */
int main(int argc, char **argv) {

  int argnum = 1; // Next argument to process
  message_t *mout, *min;
  char *dir_mem, *keyfile, *s_grpkey, *s_mgrkey, *s_gml;
  groupsig_key_t *grpkey, *mgrkey, *memkey;
  const groupsig_t *gs;  
  gml_t *gml;
  byte_t *b_grpkey, *b_mgrkey, *b_memkey, *b_gml;
  FILE *fd;
  uint64_t i, n, b_len;
  uint32_t gml_len;
  int key_format;
  uint8_t scheme, start, seq, msgs;
#ifdef PROFILE
  profile_t *prof;
  struct timeval tv_begin, tv_end;
  clock_t clck_begin, clck_end;
  uint64_t cycle_begin, cycle_end;
  uint8_t profile_skip;
#endif

  if(argc == 1) {
    fprintf(stdout, "Usage: %s <scheme> <group key> <mgr key> [<gml>] <members dir> [<n members> = 1]\n",
	    basename(argv[0]));
    return IOK;
  }

  if((groupsig_get_code_from_str(&scheme, argv[argnum])) != IOK) {
    fprintf(stderr, "Error: Wrong scheme %s\n", argv[1]);
    return IERROR;
  }
  argnum++;

  if(!(gs = groupsig_get_groupsig_from_code(scheme))) {
    return IERROR;
  }

  /* Initialize the group signature environment */
  if(groupsig_init(scheme, time(NULL)) == IERROR) {
    return IERROR;
  }

  s_grpkey = argv[argnum];
  argnum++;

  s_mgrkey = argv[argnum];
  argnum++;
  
  if(gs->desc->has_gml) {
    s_gml = argv[argnum];
    argnum++;
  }

  dir_mem = argv[argnum];
  argnum++;

  if(argc > argnum) n = atoi(argv[argnum]); else n = 1;

  /* Initialize the group key, manager key and GML variables */

  /* Group key */
  b_grpkey = NULL;
  if(misc_read_file_to_bytestring(s_grpkey, &b_grpkey, &b_len) == IERROR) {
    fprintf(stderr, "Error: failed to read group key.\n");
    return IERROR;
  }
  
  if(!(grpkey = groupsig_grp_key_import(scheme, b_grpkey, b_len))) {
    fprintf(stderr, "Error: invalid group key %s.\n", s_grpkey);
    return IERROR;
  }
  mem_free(b_grpkey); b_grpkey = NULL;

  /* Manager key */
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

  /* GML */
  gml = NULL;
  if(gs->desc->has_gml) {

    /* Read file into bytes */
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

    mem_free(b_gml); b_gml = NULL;
    
  }

#ifdef PROFILE
  if(!(prof = profile_begin("join.prf"))) {
    return IERROR;
  }
#endif

  /* Create n member keys. */
  for(i=0; i<n; i++) {

#ifdef PROFILE
    if(profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR) {
      profile_skip = 1;
    } else {
      profile_skip = 0;
    }
#endif

    if(!(memkey = groupsig_mem_key_init(scheme))) {
      return IERROR;
    }

    if(groupsig_get_joinstart(scheme, &start) == IERROR) {
      return IERROR;
    }

    if(groupsig_get_joinseq(scheme, &msgs) == IERROR) {
      return IERROR;
    }

    seq = 0;
    
    min = NULL; mout = NULL;

    /* The manager starts */
    if(!start) {

      while (seq <= msgs) {

	if(groupsig_join_mgr(&mout, gml, mgrkey, seq, min, grpkey) == IERROR) {
	  return IERROR;
	}

	if (min) { message_free(min); min = NULL; }
	min = mout; mout = NULL;
	seq++;

	if(seq > msgs) break;

	if(groupsig_join_mem(&mout, memkey, seq, min, grpkey) == IERROR) {
	  return IERROR;
	}

	if (min) { message_free(min); min = NULL; }
	min = mout; mout = NULL;
	seq++;

      }
 
    } else { /* The member starts */

      while (seq <= msgs) {

	if(groupsig_join_mem(&mout, memkey, seq, min, grpkey) == IERROR) {
	  return IERROR;
	}

	if (min) { message_free(min); min = NULL; }
	min = mout; mout = NULL;
	seq++;
	
	if(seq > msgs) break;
	
	if(groupsig_join_mgr(&mout, gml, mgrkey, seq, min, grpkey) == IERROR) {
	  return IERROR;
	}

	if (min) { message_free(min); min = NULL; }
	min = mout; mout = NULL;
	seq++;

      }
      
    }

    if (min) { message_free(min); min = NULL; }
    if (mout) { message_free(mout); mout = NULL; }

#ifdef PROFILE
    if(!profile_skip && profile_get_time(&tv_end, &clck_end, &cycle_end) == IOK) {
      profile_dump_entry(prof, &tv_begin, &tv_end, clck_begin, clck_end, cycle_begin, cycle_end);
    }

#endif

    /* Write the key into a file */
    if(!(keyfile = _keyfile_name(dir_mem, i))) {
      return IERROR;
    }

    b_memkey = NULL;
    if(groupsig_mem_key_export(&b_memkey, (uint32_t *) &b_len, memkey) == IERROR) {
      fprintf(stderr, "Error: Could not export member key.\n");
      return IERROR;
    }

    if(misc_bytes_to_file(keyfile, b_memkey, b_len) == IERROR) {
      fprintf(stderr, "Error: Could not export member key to %s.\n", keyfile);
      return IERROR;
    }
    mem_free(b_memkey); b_memkey = NULL;

    groupsig_mem_key_free(memkey); memkey = NULL;
    mem_free(keyfile); keyfile = NULL;

  }

  if(gs->desc->has_gml) {

    /* Dump the GML into a byte array */
    b_gml = NULL;
    if(gml_export(&b_gml, &gml_len, gml) == IERROR) {
      return IERROR;
    }

    /* Write the byte array into a file */
    if(!(fd = fopen(s_gml, "w"))) {
      return IERROR;
    }

    if (fwrite(b_gml, gml_len, 1, fd) != 1) {
      fclose(fd); fd = NULL;
      return IERROR;
    }

    fclose(fd); fd = NULL;    
    
  }

  /* 3. Done. */
  groupsig_mgr_key_free(mgrkey); mgrkey = NULL;
  groupsig_grp_key_free(grpkey); grpkey = NULL;

  if(gs->desc->has_gml) {
    gml_free(gml); gml = NULL;
  }

  groupsig_clear(scheme);
  
#ifdef PROFILE
  profile_free(prof); prof = NULL;
#endif
  
  return IOK;

}

/* join.c ends here */
