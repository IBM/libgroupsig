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
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>        
#include <sys/stat.h>
#include <stdarg.h>
#include <libgen.h>

#include "groupsig.h"
#include "gml.h"
#include "kty04.h"

#include "types.h"
#include "sys/mem.h"
#include "misc/misc.h"

extern char *optarg;
extern int optind, opterr, optopt;
log_t logger;
sysenv_t *sysenv;

/* @todo: Error management and memory cleanup. */
int main(int argc, char **argv) {

  char *s_scheme, *s_key_type, *s_key_format, *s_key_file, *s_key, *s_grp_key_file;
  groupsig_key_t *grpkey, *mgrkey, *memkey;
  int scheme, key_type, key_format;

  if (argc <= 1 || !strcmp(argv[1], "-h")) {
    fprintf(stdout, "Usage: %s <scheme> <key type> <key format> <key file> [<grp key file>]\n", argv[0]);
    return IOK;
  }

  if (argc < 5) {
    fprintf(stderr, "Usage: %s <scheme> <key type> <key format> <key file> [<grp key file>]\n", argv[0]);
    return IOK;    
  }

  s_scheme = argv[1];
  s_key_type = argv[2];
  s_key_format = argv[3];
  s_key_file = argv[4];

  grpkey = mgrkey = memkey = NULL;
  
  if(argc == 6) s_grp_key_file = argv[5];

  /* Scheme */
  if (!strcmp(s_scheme, "KTY04")) {
    scheme = GROUPSIG_KTY04_CODE;
  } else if (!strcmp(s_scheme, "BBS04")) {
    scheme = GROUPSIG_BBS04_CODE;
  } else if (!strcmp(s_scheme, "CPY06")) {
    scheme = GROUPSIG_CPY06_CODE;
  } else {
    fprintf(stderr, "Unknown scheme.\n");
    return IERROR;
  }

  /* Key type */
  if (!strcmp(s_key_type, "MGR")) {
    key_type = 0;
  } else if (!strcasecmp(s_key_type, "GRP")) {
    key_type = 1;
  } else if (!strcasecmp(s_key_type, "MEM")) {
    key_type = 2;
  } else {
    fprintf(stderr, "Unknown key type.\n");
    return IERROR;
  }

  /* Key format */
  if (!strcasecmp(s_key_format, "FILE_NULL_B64")) {
    key_format = GROUPSIG_KEY_FORMAT_FILE_NULL_B64;
  } else if (!strcasecmp(s_key_format, "FILE_NULL")) {
    key_format = GROUPSIG_KEY_FORMAT_FILE_NULL;
  } else {
    fprintf(stderr, "Unknown key format.\n");
    return IERROR;
  }

  /* @todo This should not be necessary... */
  if(groupsig_init(time(NULL)) == IERROR) {
    return IERROR;
  }

  /* Temporarily, for CPY06, we require the group key to be loaded
     before any other key... This is a todo (tradeoff usability vs costs) 
  */
  if (scheme == GROUPSIG_CPY06_CODE && key_type != 1) {

    if (!(grpkey = groupsig_grp_key_import(scheme, key_format, s_grp_key_file))) {
      fprintf(stderr, "Error: invalid group key %s.\n", s_key_file);
      return IERROR;
    }
    
  }

  /* Import the key, convert it to a printable string and print it */
  if (key_type == 0) { /* Manager key */

    if (!(mgrkey = groupsig_mgr_key_import(scheme, key_format, s_key_file))) {
      fprintf(stderr, "Error: invalid manager key %s.\n", s_key_file);
      return IERROR;
    }

    if (!(s_key = groupsig_mgr_key_to_string(mgrkey))) {
      return IERROR;
    }

    fprintf(stdout, 
	    "------------------------------------------------------------\n"
	    "                     GROUP MANAGER KEY                      \n\n"
	    /* "%s\n\n" */
	    "------------------------------------------------------------\n"/* , */
	    /* s_key) */);
    misc_fprintf_tabulated(stdout, 1, 80, s_key);
    fprintf(stdout, "\n\n");

    groupsig_mgr_key_free(mgrkey); mgrkey = NULL;

  } else if (key_type == 1) { /* Group key */ 
    
    if (!grpkey) {

      if (!(grpkey = groupsig_grp_key_import(scheme, key_format, s_key_file))) {
	fprintf(stderr, "Error: invalid group key %s.\n", s_key_file);
	return IERROR;
      }

    }

    if (!(s_key = groupsig_grp_key_to_string(grpkey))) {
      return IERROR;
    }

    fprintf(stdout, 
	    "------------------------------------------------------------\n"
	    "                          GROUP KEY                         \n\n"
	    /* "%s\n\n" */
	    "------------------------------------------------------------\n"/* , */
	    /* s_key */);
    
    misc_fprintf_tabulated(stdout, 1, 80, s_key);
    fprintf(stdout, "\n\n");

    groupsig_grp_key_free(grpkey); grpkey = NULL;

  } else { /* Member key */
   
    if (!(memkey = groupsig_mem_key_import(scheme, key_format, s_key_file))) {
      fprintf(stderr, "Error: invalid member key %s.\n", s_key_file);
      return IERROR;
    }

    if (!(s_key = groupsig_mem_key_to_string(memkey))) {
      return IERROR;
    }

    fprintf(stdout, 
	    "------------------------------------------------------------\n"
	    "                      GROUP MEMBER KEY                      \n\n"
	    "%s\n\n"
	    "------------------------------------------------------------\n",
	    s_key);

    groupsig_mem_key_free(memkey); memkey = NULL;
    
  }
  
  if(s_key) { mem_free(s_key); s_key = NULL; }
  return IOK;

}

/* print_key.c ends here */
