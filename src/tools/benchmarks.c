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
#include "misc/profile.h"

log_t logger;
sysenv_t *sysenv;

int
_setup_benchmark
(
 uint8_t code,
 char *filename,
 uint32_t iters
 ) {
  
  const groupsig_t *gh;
  groupsig_key_t *grpkey, *mgrkey;
  gml_t *gml;
  profile_t *prof;
  struct timeval tv_begin, tv_end;  
  clock_t clck_begin, clck_end;
  uint64_t cycle_begin, cycle_end;  
  uint32_t i;
  int rc;

  if (!filename || !iters) {
    fprintf(stderr, "_setup_benchmark: wrong parameters.\n");
    return IERROR;
  }

  grpkey = NULL;
  mgrkey = NULL;
  gml = NULL;
  prof = NULL;
  rc = IOK;
  
  if (!(gh = groupsig_get_groupsig_from_code(code))) {
    return IERROR;
  }
  
  prof = profile_begin(filename);
  if (!prof) {
    return IERROR;
  }

  for (i=0; i<iters; i++) {

    if (!(grpkey = groupsig_grp_key_init(code)))
      return IERROR;
    
    if (!(mgrkey = groupsig_mgr_key_init(code)))
      GOTOENDRC(IERROR, _setup_benchmark);
    
    if (gh->desc->has_gml)
      if (!(gml = gml_init(code)))
	GOTOENDRC(IERROR, _setup_benchmark);

    if (profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR)
      GOTOENDRC(IERROR, _setup_benchmark);
    
    if (groupsig_setup(code, grpkey, mgrkey, gml) == IERROR)
      GOTOENDRC(IERROR, _setup_benchmark);
    
    if (profile_get_time(&tv_end, &clck_end, &cycle_end) == IERROR)
      GOTOENDRC(IERROR, _setup_benchmark);
    
    if (profile_add_entry(prof,
			  &tv_begin, &tv_end,
			  clck_begin, clck_end,
			  cycle_begin, cycle_end) == IERROR)
      GOTOENDRC(IERROR, _setup_benchmark);

  }

  if (profile_process_and_dump(prof, code, "setup") == IERROR)
    GOTOENDRC(IERROR, _setup_benchmark);
    
 _setup_benchmark_end:
  
  if (grpkey) { groupsig_grp_key_free(grpkey); grpkey = NULL; }
  if (mgrkey) { groupsig_mgr_key_free(mgrkey); mgrkey = NULL; }
  if (gml && gh->desc->has_gml) { gml_free(gml); gml = NULL; }
  if (prof) { profile_free(prof); prof = NULL; }
  
  return rc;
  
}

int
_join_benchmark
(
 uint8_t code,
 char *filename,
 uint32_t iters
 ) {

  const groupsig_t *gh;
  groupsig_key_t *grpkey, *mgrkey, *memkey;
  message_t *mout, *min;
  gml_t *gml;
  profile_t *prof;
  struct timeval tv_begin, tv_end;  
  clock_t clck_begin, clck_end;
  uint64_t cycle_begin, cycle_end;  
  uint32_t i;
  uint8_t start, seq, msgs;
  int rc;

  if (!filename || !iters) {
    fprintf(stderr, "_join_benchmark: wrong parameters.\n");
    return IERROR;
  }

  grpkey = NULL;
  mgrkey = NULL;
  gml = NULL;
  prof = NULL;
  rc = IOK;
  
  if (!(gh = groupsig_get_groupsig_from_code(code))) {
    return IERROR;
  }
  
  prof = profile_begin(filename);
  if (!prof) {
    return IERROR;
  }

  for (i=0; i<iters; i++) {

    if (!(grpkey = groupsig_grp_key_init(code)))
      return IERROR;
    
    if (!(mgrkey = groupsig_mgr_key_init(code)))
      GOTOENDRC(IERROR, _join_benchmark);

    if(!(memkey = groupsig_mem_key_init(code)))
      GOTOENDRC(IERROR, _join_benchmark);
    
    if (gh->desc->has_gml)
      if (!(gml = gml_init(code)))
	GOTOENDRC(IERROR, _join_benchmark);
    
    if (groupsig_setup(code, grpkey, mgrkey, gml) == IERROR)
      GOTOENDRC(IERROR, _join_benchmark);

    if (profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR)
      GOTOENDRC(IERROR, _join_benchmark);

    //////

    if(groupsig_get_joinstart(code, &start) == IERROR) {
      return IERROR;
    }

    if(groupsig_get_joinseq(code, &msgs) == IERROR) {
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

    if (memkey) { groupsig_mem_key_free(memkey); memkey = NULL; }
    if (min) { message_free(min); min = NULL; }
    if (mout) { message_free(mout); mout = NULL; }    
    
    //////
    
    if (profile_get_time(&tv_end, &clck_end, &cycle_end) == IERROR)
      GOTOENDRC(IERROR, _join_benchmark);
    
    if (profile_add_entry(prof,
			  &tv_begin, &tv_end,
			  clck_begin, clck_end,
			  cycle_begin, cycle_end) == IERROR)
      GOTOENDRC(IERROR, _join_benchmark);

  }

  if (profile_process_and_dump(prof, code, "join") == IERROR)
    GOTOENDRC(IERROR, _join_benchmark);
    
 _join_benchmark_end:
  
  if (grpkey) { groupsig_grp_key_free(grpkey); grpkey = NULL; }
  if (mgrkey) { groupsig_mgr_key_free(mgrkey); mgrkey = NULL; }
  if (memkey) { groupsig_mem_key_free(memkey); memkey = NULL; }
  if (gml && gh->desc->has_gml) { gml_free(gml); gml = NULL; }
  if (prof) { profile_free(prof); prof = NULL; }
  
  return rc;
  
}

int main(int argc, char *argv[]) {
  
  const groupsig_t *gh;
  char *filename;
  FILE *fd;
  uint64_t uint64;
  uint32_t iters;
  uint8_t code;

  if(argc == 1) {
    fprintf(stdout, "Usage: %s <iters> <output file>\n",
	    basename(argv[0]));
    return IOK;
  }

  errno = 0;
  uint64 = strtoul(argv[1], NULL, 10);
  if(errno || uint64 > UINT32_MAX) {
    fprintf(stderr, "Error: parsing iters.\n");
    return IERROR;
  }
  iters = (uint32_t) uint64;  

  /* 
     Iterate through the codes of the supported schemes.
     This is very dirty, but there is currently no way to retrieve the codes of 
     all supported schemes. Change if one becomes available.
  */
  filename = argv[2];

  fd = fopen(filename, "a");
  if (!fd) {
    return IERROR;
  }

  fprintf(fd,
	  "#Times are in microseconds\n"
	  "#code\toperation\tavg user time\tstd user time\tavg cpu time\tstd cpu time\n");
  fclose(fd); fd = NULL;
  
  
  for (code=0; code<UINT8_MAX; code++) {
    
    if (!groupsig_is_supported_scheme(code)) continue;

      if (groupsig_init(code, 0) == IERROR) {
	fprintf(stderr, "Error initializing scheme with code %u\n", code);
	return IERROR;
      }

      if (!(gh = groupsig_get_groupsig_from_code(code))) {
	fprintf(stderr, "Error getting handle for scheme with code %u\n",
		code);
	return IERROR;	
      }

      if (_setup_benchmark(code, filename, iters) == IERROR) {
	fprintf(stderr, "Error benchmarking setup for scheme with code %u\n",
		code);
	return IERROR;
      }

      if (_join_benchmark(code, filename, iters) == IERROR) {
	fprintf(stderr, "Error benchmarking join-issue for scheme with code %u\n",
		code);
	return IERROR;
      }

      /* if (_sign_benchmark(code, filename, iters) == IERROR) { */
      /* 	fprintf(stderr, "Error benchmarking sign for scheme with code %u\n", */
      /* 		code); */
      /* 	return IERROR; */
      /* } */

      /* if (_verify_benchmark(code, filename, iters) == IERROR) { */
      /* 	fprintf(stderr, "Error benchmarking verify for scheme with code %u\n", */
      /* 		code); */
      /* 	return IERROR; */
      /* } */

      /* if (gh->verify_batch) { */
      /* 	if (_verify_batch_benchmark(code, filename, iters) == IERROR) { */
      /* 	  fprintf(stderr, "Error benchmarking verify_batch for scheme with code %u\n", */
      /* 		  code); */
      /* 	  return IERROR; */
      /* 	} */
      /* } */

      /* if (gh->open) { */
      /* 	if (_open_benchmark(code, filename, iters) == IERROR) { */
      /* 	  fprintf(stderr, "Error benchmarking open for scheme with code %u\n", */
      /* 		  code); */
      /* 	  return IERROR; */
      /* 	} */
      /* } */

      /* if (gh->open_verify) { */
      /* 	if (_open_verify_benchmark(code, filename, iters) == IERROR) { */
      /* 	  fprintf(stderr, "Error benchmarking open verify for scheme with code %u\n", */
      /* 		  code); */
      /* 	  return IERROR; */
      /* 	} */
      /* } */

      /* if (gh->reveal) { */
      /* 	if (_reveal_benchmark(code, filename, iters) == IERROR) { */
      /* 	  fprintf(stderr, "Error benchmarking reveal for scheme with code %u\n", */
      /* 		  code); */
      /* 	  return IERROR; */
      /* 	} */
      /* } */

      /* if (gh->trace) { */
      /* 	if (_trace_benchmark(code, filename, iters) == IERROR) { */
      /* 	  fprintf(stderr, "Error benchmarking trace for scheme with code %u\n", */
      /* 		  code); */
      /* 	  return IERROR; */
      /* 	} */
      /* } */

      /* if (gh->claim) { */
      /* 	if (_claim_benchmark(code, filename, iters) == IERROR) { */
      /* 	  fprintf(stderr, "Error benchmarking claim for scheme with code %u\n", */
      /* 		  code); */
      /* 	  return IERROR; */
      /* 	} */
      /* } */

      /* if (gh->claim_verify) { */
      /* 	if (_claim_verify_benchmark(code, filename, iters) == IERROR) { */
      /* 	  fprintf(stderr, "Error benchmarking claim verify for scheme with code %u\n", */
      /* 		  code); */
      /* 	  return IERROR; */
      /* 	} */
      /* } */

      /* if (gh->prove_equality) { */
      /* 	if (_prove_equality_benchmark(code, filename, iters) == IERROR) { */
      /* 	  fprintf(stderr, "Error benchmarking prove_equality for scheme with code %u\n", */
      /* 		  code); */
      /* 	  return IERROR; */
      /* 	} */
      /* } */

      /* if (gh->prove_equality_verify) { */
      /* 	if (_prove_equality_verify_benchmark(code, filename, iters) == IERROR) { */
      /* 	  fprintf(stderr, "Error benchmarking prove_equality_verify for scheme with code %u\n", */
      /* 		  code); */
      /* 	  return IERROR; */
      /* 	} */
      /* } */

      /* if (gh->blind) { */
      /* 	if (_blind_benchmark(code, filename, iters) == IERROR) { */
      /* 	  fprintf(stderr, "Error benchmarking blind for scheme with code %u\n", */
      /* 		  code); */
      /* 	  return IERROR; */
      /* 	} */
      /* } */

      /* if (gh->convert) { */
      /* 	if (_convert_benchmark(code, filename, iters) == IERROR) { */
      /* 	  fprintf(stderr, "Error benchmarking convert for scheme with code %u\n", */
      /* 		  code); */
      /* 	  return IERROR; */
      /* 	} */
      /* } */

      /* if (gh->unblind) { */
      /* 	if (_unblind_benchmark(code, filename, iters) == IERROR) { */
      /* 	  fprintf(stderr, "Error benchmarking unblind for scheme with code %u\n", */
      /* 		  code); */
      /* 	  return IERROR; */
      /* 	} */
      /* } */

      /* if (gh->identify) { */
      /* 	if (_identify_benchmark(code, filename, iters) == IERROR) { */
      /* 	  fprintf(stderr, "Error benchmarking identify for scheme with code %u\n", */
      /* 		  code); */
      /* 	  return IERROR; */
      /* 	} */
      /* } */

      /* if (gh->link) { */
      /* 	if (_link_benchmark(code, filename, iters) == IERROR) { */
      /* 	  fprintf(stderr, "Error benchmarking link for scheme with code %u\n", */
      /* 		  code); */
      /* 	  return IERROR; */
      /* 	} */
      /* } */

      /* if (gh->verify_link) { */
      /* 	if (_verify_link_benchmark(code, filename, iters) == IERROR) { */
      /* 	  fprintf(stderr, "Error benchmarking verify_link for scheme with code %u\n", */
      /* 		  code); */
      /* 	  return IERROR; */
      /* 	} */
      /* } */

      /* if (gh->seqlink) { */
      /* 	if (_seqlink_benchmark(code, filename, iters) == IERROR) { */
      /* 	  fprintf(stderr, "Error benchmarking seqlink for scheme with code %u\n", */
      /* 		  code); */
      /* 	  return IERROR; */
      /* 	} */
      /* } */

      /* if (gh->verify_seqlink) { */
      /* 	if (_verify_seqlink_benchmark(code, filename, iters) == IERROR) { */
      /* 	  fprintf(stderr, "Error benchmarking verify_seqlink for scheme with code %u\n", */
      /* 		  code); */
      /* 	  return IERROR; */
      /* 	} */
      /* } */

      if (groupsig_clear(code) == IERROR) {
	fprintf(stderr, "Error clearing scheme with code %u\n", code);
	return IERROR;
      }

  }

  return IOK;
  
}

/* benchmarks.c ends here */
