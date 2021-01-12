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

#include "sysenv.h"
#include "groupsig.h"
#include "gml.h"
/* #include "kty04.h" */
#include "types.h"
#include "logger.h"

#include "sys/mem.h"
#include "misc/misc.h"

#ifdef PROFILE
#include "misc/profile.h"
#endif

#define DFLT_DIR_MODE S_IRWXU | S_IRWXG
#define DFLT_GRPKEY_FILE "grp.key"
#define DFLT_MGRKEY_FILE "mgr.key"
#define DFLT_CNVKEY_FILE "csk.key"
#define DFLT_GML_FILE "gml"
#define DFLT_CRL_FILE "crl"

extern char *optarg;
extern int optind, opterr, optopt;
log_t logger;
sysenv_t *sysenv;

struct option long_options[] = {
  {"help", no_argument, 0, 0}, /* 'h', Help request */
  {"gs-base", required_argument, 0, 0}, /* 'd:', base directory for groupsig info. */
  {"gs-mgr", required_argument, 0, 0}, /* 'M:', relative directory for groupsig manager info. */
  {"gs-mem", required_argument, 0, 0}, /* 'm:', relative directory for groupsig member info. */
  {"gs-grp", required_argument, 0, 0}, /* 'g:', relative directory for groupsig public group info. */
  {"prime-size", required_argument, 0, 0}, /* 'p:', prime size for group keys in KTY04. */
  /* {"bit-limit", required_argument, 0, 0}, /\* b: bit limit parameter for BBS04 and CPY06. *\/ */
  {NULL, 0, 0, 0}
};

#define OPT_STRING "hd:M:m:g:p:b:n:"

/**
 * @struct options_t
 */
typedef struct {

  uint8_t scheme;
  
  /* Directories */

  /* Group signature */
  char *gs_base; /**< Base directory for storing groupsig related info. */
  char *gs_mgr; /**< Relative directory for storing groupsig manager info. */
  char *gs_mem; /**< Relative directory for storing groupsig members info. */
  char *gs_grp; /**< Relative directory for storing groupsig public group info. */

#ifdef PROFILE
  uint64_t n; /**< Number of iterations to run. */
#endif

} options_t;

char* str_ncat(int n, const char *fmt, ...) {

  va_list ap;
  char **s, *str;
  uint64_t len;
  int i;
  
  if(!fmt || n <= 0) {
    fprintf(stderr, "Error: %s\n", strerror(EINVAL));
    return NULL;
  }

  if(!(s = (char **) mem_malloc(sizeof(char *)*n))) {
    return NULL;
  } 

  len = 0;
  va_start(ap, fmt);
  for(i=0; i<n; i++) {
    s[i] = va_arg(ap, char *);
    len += strlen(s[i]);    
  }
  va_end(ap);

  if(!(str = (char *) mem_malloc(sizeof(char)*(len+1)))) {
    mem_free(s); s = NULL;
    return NULL;
  }

  for(i=0; i<n; i++) strcpy(&str[strlen(str)], s[i]);

  mem_free(s); s = NULL;

  return str;

}

static int _options_help(char **argv) {

  if(!argv) {
    fprintf(stderr, "No options received.");
    return IERROR;
  }

  fprintf(stderr, "Usage: %s <scheme> -d <GS base dir> -M <GS Manager subdir> -g <GS group public data subdir> "
    "-m <GS members subdir> [-p <prime size>] [-b <bit limit>]\n", basename(argv[0]));

  return IOK;

}

static int _options_check(options_t *opt) {

  if(!opt) {
    fprintf(stderr, "No options received.");
    return IERROR;
  }

  /* Currently, all options are required */
  if(!opt->gs_base) {
    fprintf(stderr, "Error: --gs-basedir (-d) is required.\n");
    return IERROR;
  }

  if(!opt->gs_mgr) {
    fprintf(stderr, "Error: --gs-mgr (-M) is required.\n");
    return IERROR;
  }

  if(!opt->gs_mem) {
    fprintf(stderr, "Error: --gs-mem (-m) is required.\n");
    return IERROR;
  }

  if(!opt->gs_grp) {
    fprintf(stderr, "Error: --gs-grp (-g) is required.\n");
    return IERROR;
  }

#ifdef PROFILE
  if(!opt->n) {
    fprintf(stderr, "Error: -n is required.\n");
    return IERROR;
  }
#endif

  return IOK;

}

static int _options_parse(options_t *opt, int argc, char **argv) {

  uint64_t uint64;
  int ret, option_index;
  uint8_t scheme;

  if(!opt) {
    fprintf(stderr, "Error: %s\n", strerror(EINVAL));
    return IERROR;
  }

  if(argc <= 1 || !argv) {
    _options_help(argv);
    exit(IOK);
  }

  /* First parameter: scheme */
  if((groupsig_get_code_from_str(&opt->scheme, argv[1])) == IERROR) {
    fprintf(stderr, "Error: Wrong scheme %s\n", argv[1]);
    return IERROR;
  }
  
  if(groupsig_init(opt->scheme, time(NULL)) == IERROR) {
    return IERROR;
  }

  optind++;
  opterr = 1;   /* We want error messages here... */
  ret = 0;

  while((ret = getopt_long(argc, argv, OPT_STRING, long_options, &option_index)) != -1) {

    switch(ret) {
    case 0:

    /* 0 means long option */
    if(!strcmp(long_options[option_index].name, "help")) {
      _options_help(argv);
      return IOK;
    } else if(!strcmp(long_options[option_index].name, "gs-base")) {
      if(!(opt->gs_base = strdup(optarg))) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return IERROR;
      }
    } else if(!strcmp(long_options[option_index].name, "gs-mgr")) {
      if(!(opt->gs_mgr = strdup(optarg))) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return IERROR;
      }
    } else if(!strcmp(long_options[option_index].name, "gs-mem")) {
      if(!(opt->gs_mem = strdup(optarg))) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return IERROR;
      }
    } else if(!strcmp(long_options[option_index].name, "gs-grp")) {
      if(!(opt->gs_grp = strdup(optarg))) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return IERROR;
      }
    } /* else if(!strcmp(long_options[option_index].name, "prime-size")) { */

    /*   /\* prime-size only for KTY04 *\/ */
    /*   if(opt->cfg->scheme == GROUPSIG_KTY04_CODE) { */
    /*     errno = 0; */
    /*     uint64 = strtoul(optarg, NULL, 10); */
    /*     if(errno) { */
    /*       fprintf(stderr, "Error: %s\n", strerror(errno)); */
    /*       return IERROR; */
    /*     } */

    /*     /\* Actually, what our implementation of KTY04 requires is the size of the */
    /*      Sophie-Germain primes. *\/ */
    /*     ((kty04_config_t *) opt->cfg->config)->primesize = uint64/4; */
    /*   } else { */
    /*     fprintf(stderr, "Warning: --prime-size is only available for KTY04. Ignoring.\n"); */
    /*     //return IERROR; */

    /*   } */

    /* } */ /* else if(!strcmp(long_options[option_index].name, "bit-limit")) { */

    /*   /\* bit-limit only for BBS04 *\/ */
    /*   if(opt->cfg->scheme == GROUPSIG_BBS04_CODE || */
    /*       opt->cfg->scheme == GROUPSIG_CPY06_CODE) { */

    /*     errno = 0; */
    /*     uint64 = strtoul(optarg, NULL, 10); */
    /*     if(errno) { */
    /*       fprintf(stderr, "Error: %s\n", strerror(errno)); */
    /*       return IERROR; */
    /*     } */

    /*     if(opt->cfg->scheme == GROUPSIG_BBS04_CODE) { */
    /*       ((bbs04_config_t *) opt->cfg->config)->bitlimit = uint64; */
    /*     } else { */
    /*       ((cpy06_config_t *) opt->cfg->config)->bitlimit = uint64; */
    /*     } */
    /*   } else { */
    /*     fprintf(stderr, "Warning:: --bit-limit is only available for BBS04 and CPY06. Ignoring.\n"); */
    /*     //return IERROR; */
    /*   } */

    /* } */ else { /* Wat? */
      fprintf(stderr, "Error: Unknon option --%s.\n", long_options[option_index].name);
      return IERROR;
    }

    break;

    case 'h': /* help */
      _options_help(argv);
      return IOK;
    break;

    case 'd': /* gs-base */
      if(!(opt->gs_base = strdup(optarg))) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return IERROR;
      }
    break;

    case 'M': /* gs-mgr */
      if(!(opt->gs_mgr = strdup(optarg))) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return IERROR;
      }
    break;

    case 'm': /* gs-mem */
      if(!(opt->gs_mem = strdup(optarg))) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return IERROR;
      }
    break;

    case 'g': /* gs-grp */
      if(!(opt->gs_grp = strdup(optarg))) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return IERROR;
      }
    break;

    /* case 'p': /\* prime-size *\/ */

    /*   /\* prime-size only for KTY04 *\/ */
    /*   if(opt->cfg->scheme == GROUPSIG_KTY04_CODE) { */

    /*     errno = 0; */
    /*     uint64 = strtoul(optarg, NULL, 10); */
    /*     if(errno) { */
    /*       fprintf(stderr, "Error: %s\n", strerror(errno)); */
    /*       return IERROR; */
    /*     } */

    /*     /\* Actually, what our implementation of KTY04 requires is the size of the */
    /*      Sophie-Germain primes. *\/ */
    /*     ((kty04_config_t *) opt->cfg->config)->primesize = uint64/4; */
    /*   } else { */
    /*     fprintf(stderr, "Warning: -p is only available for KTY04. Ignoring.\n"); */
    /*     //return IERROR; */
    /*   } */
    /* break; */

    /* case 'b': /\* bit-limit *\/ */

    /*   /\* bit-limit only for BBS04 *\/ */
    /*   if(opt->cfg->scheme == GROUPSIG_BBS04_CODE || */
    /*       opt->cfg->scheme == GROUPSIG_CPY06_CODE) { */

    /*     errno = 0; */
    /*     uint64 = strtoul(optarg, NULL, 10); */
    /*     if(errno) { */
    /*       fprintf(stderr, "Error: %s\n", strerror(errno)); */
    /*       return IERROR; */
    /*     } */

    /*     if(opt->cfg->scheme == GROUPSIG_BBS04_CODE) { */
    /*       ((bbs04_config_t *) opt->cfg->config)->bitlimit = uint64; */
    /*     } else { */
    /*       ((cpy06_config_t *) opt->cfg->config)->bitlimit = uint64; */
    /*     } */
    /*   } */
    /*   else{ */
    /*     fprintf(stderr, "Warning: -b is only available for BBS04 and CPY06. Ignoring.\n"); */
    /*     //return IERROR; */
    /*   } */

    /*   break; */

  #ifdef PROFILE
    case 'n': /* iterations */
      errno = 0;
      uint64 = strtoul(optarg, NULL, 10);
      if(errno) {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return IERROR;
      }
      opt->n = uint64;
    break;
  #endif

    case '?': /* Character not included in optstring */
      fprintf(stderr, "Error: Unknown option -%c.\n", (char) ret);
      return IERROR;

    default:
      /* This should not happen. However... */
      fprintf(stderr, "Error: Unknown option -%c.\n", (char) ret);
      return IERROR;
    }

  }

  return _options_check(opt);

}

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

  options_t opt = {
    UINT8_MAX, /* scheme */
    NULL, /* char *gs_base; */
    NULL, /* char *gs_mgr; */
    NULL, /* char *gs_mem; */
    NULL, /* char *gs_grp; */
    /* 0, /\* uint64_t n *\/ */
  };
  char *dir_gs_mgr, *dir_gs_mem, *dir_gs_grp, *keyfile;
  groupsig_key_t *grpkey, *mgrkey, *mgrkey2;
  const groupsig_t *gs;
  gml_t *gml;
  byte_t *b_mgrkey, *b_grpkey, *b_gml;
  FILE *fd;
  uint32_t b_len, gml_len;
#ifdef PROFILE
  uint64_t i;
  profile_t *prof;
  struct timeval tv_begin, tv_end;
  clock_t clck_begin, clck_end;
  uint64_t cycle_begin, cycle_end;
  uint8_t profile_skip;
#endif
  int key_format;

  /* pbc_set_msg_to_stderr(0); */
  if(_options_parse(&opt, argc, argv) == IERROR) {
    return IERROR;
  }

  log_init("group_create.log", LOGDEBUG, 1, &logger);

  /* 1. Create directory structure. */

  /* Base directory for group signature info. */
  if(mkdir(opt.gs_base, DFLT_DIR_MODE) == -1) {
    fprintf(stderr, "Error: %s\n", strerror(errno));
    return IERROR;
  }

  /* Directory for group manager info  */
  if(!(dir_gs_mgr = str_ncat(3, "%s %s %s", opt.gs_base, "/", opt.gs_mgr))) {
    return IERROR;
  }

  if(mkdir(dir_gs_mgr, DFLT_DIR_MODE) == -1) {
    fprintf(stderr, "Error: %s\n", strerror(errno));
    return IERROR;
  }

  /* Directory for group members info */
  if(!(dir_gs_mem = str_ncat(3, "%s %s %s", opt.gs_base, "/", opt.gs_mem))) {
    return IERROR;
  }

  if(mkdir(dir_gs_mem, DFLT_DIR_MODE) == -1) {
    fprintf(stderr, "Error: %s\n", strerror(errno));
    return IERROR;
  }

  /* Directory for public group info */
  if(!(dir_gs_grp = str_ncat(3, "%s %s %s", opt.gs_base, "/", opt.gs_grp))) {
    return IERROR;
  }

  if(mkdir(dir_gs_grp, DFLT_DIR_MODE) == -1) {
    fprintf(stderr, "Error: %s\n", strerror(errno));
    return IERROR;
  }

#ifdef PROFILE
  if(!(prof = profile_begin("group_create.prf"))) {
    return IERROR;
  }
  
  for(i=0; i<opt.n; i++) {
#endif

    /* 2. Create group keys. */
    /* if(groupsig_init(time(NULL)) == IERROR) { */
    /*   return IERROR; */
    /* } */

    /* Initialize the group key, manager key and GML variables */
    if(!(mgrkey = groupsig_mgr_key_init(opt.scheme))) {
      return IERROR;
    }

    /* In GL19, we have two manager keys */
    if(opt.scheme == GROUPSIG_GL19_CODE) {
      if(!(mgrkey2 = groupsig_mgr_key_init(opt.scheme))) {
	return IERROR;
      }
    }

    if(!(gs = groupsig_get_groupsig_from_code(opt.scheme))) {
      return IERROR;
    }

    if(!(grpkey = groupsig_grp_key_init(opt.scheme))) {
      return IERROR;
    }
    
    gml = NULL;
    if(gs->desc->has_gml) {
      if(!(gml = gml_init(opt.scheme))) {
	fprintf(stderr, "Error: invalid GML.\n");
	return IERROR;
      }
    }    

#ifdef PROFILE
    if(profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR) {
      profile_skip = 1;
    } else {
      profile_skip = 0;
    }
#endif

    /* "Construct" the group (this actually fills the keys and GML with
       all the cryptographic data) */
    if(groupsig_setup(opt.scheme, grpkey, mgrkey, gml) == IERROR) {
      fprintf(stdout, "Setup went wrong\n");
      return IERROR;
    }

    /* In GL19, we have to call the setup function twice. */
    if (opt.scheme == GROUPSIG_GL19_CODE) {
      if(groupsig_setup(opt.scheme, grpkey, mgrkey2, gml) == IERROR) {
	fprintf(stdout, "Setup went wrong\n");
	return IERROR;
      }
    }

#ifdef PROFILE
    if(!profile_skip && profile_get_time(&tv_end, &clck_end, &cycle_end) == IOK) {
      profile_dump_entry(prof, &tv_begin, &tv_end, clck_begin, clck_end, cycle_begin, cycle_end);
    }

#endif
    
    /* Manager key */
    if(!(keyfile = str_ncat(3, "%s %s %s", dir_gs_mgr,
          "/", DFLT_MGRKEY_FILE))) {
      return IERROR;
    }

    b_mgrkey = NULL;
    if(groupsig_mgr_key_export(&b_mgrkey, &b_len, mgrkey) == IERROR) {
      fprintf(stderr, "Error: Could not export manager key.\n");      
      return IERROR;
    }

    if(misc_bytes_to_file(keyfile, b_mgrkey, b_len) == IERROR) {
      fprintf(stderr, "Error: Could not export manager key to %s.\n", keyfile);
      return IERROR;
    }
    mem_free(b_mgrkey); b_mgrkey = NULL;

    mem_free(keyfile);

    /* In GL19, we have two manager keys */
    if(opt.scheme == GROUPSIG_GL19_CODE) {

      if(!(keyfile = str_ncat(3, "%s %s %s", dir_gs_mgr,
			      "/", DFLT_CNVKEY_FILE))) {
	return IERROR;
      }

      b_mgrkey = NULL;
      if(groupsig_mgr_key_export(&b_mgrkey, &b_len, mgrkey2) == IERROR) {
	return IERROR;
      }

      if(misc_bytes_to_file(keyfile, b_mgrkey, b_len) == IERROR) {
	fprintf(stderr, "Error: Could not export manager key to %s.\n", keyfile);
	return IERROR;
      }
      mem_free(b_mgrkey); b_mgrkey = NULL;
      
      mem_free(keyfile);
	  
    }
  
    /* Group key */
    if(!(keyfile = str_ncat(3, "%s %s %s", dir_gs_grp, "/", DFLT_GRPKEY_FILE))) {
      return IERROR;
    }

    b_grpkey = NULL;
    if(groupsig_grp_key_export(&b_grpkey, &b_len, grpkey) == IERROR) {
      return IERROR;
    }

    if(misc_bytes_to_file(keyfile, b_grpkey, b_len) == IERROR) {
      fprintf(stderr, "Error: Could not export group key to %s.\n", keyfile);
      return IERROR;
    }
    mem_free(b_grpkey); b_grpkey = NULL;
  
    mem_free(keyfile);

    /* GML */
    if(gs->desc->has_gml) {
      if(!(keyfile = str_ncat(3, "%s %s %s", dir_gs_mgr, "/", DFLT_GML_FILE))) {
	return IERROR;
      }
      
      /* Dump the GML into a byte array */
      b_gml = NULL;
      if(gml_export(&b_gml, &gml_len, gml) == IERROR) {
	return IERROR;
      }

      /* Write the byte array into a file */
      if(!(fd = fopen(keyfile, "w"))) {
	return IERROR;
      }

      if (fwrite(b_gml, gml_len, 1, fd) != 1) {
	fclose(fd); fd = NULL;
	return IERROR;
      }
      
      fclose(fd); fd = NULL;    
      mem_free(keyfile); keyfile = NULL;
      
    }

    /* 3. Done. Free stuff. */
    groupsig_mgr_key_free(mgrkey); mgrkey = NULL;
    groupsig_grp_key_free(grpkey); grpkey = NULL;
    
    if(gs->desc->has_gml) {
      gml_free(gml); gml = NULL;
    }
    
#ifdef PROFILE
  }

  profile_free(prof); prof = NULL;
#endif
  
  groupsig_clear(opt.scheme);
  mem_free(dir_gs_mgr); dir_gs_mgr = NULL;
  mem_free(dir_gs_grp); dir_gs_grp = NULL;  
  mem_free(dir_gs_mem); dir_gs_mem = NULL;
  mem_free(opt.gs_base); opt.gs_base = NULL;
  mem_free(opt.gs_mgr); opt.gs_mgr = NULL;
  mem_free(opt.gs_grp); opt.gs_grp = NULL;
  mem_free(opt.gs_mem); opt.gs_mem = NULL;
  log_free(&logger);

  return IOK;

}

/* group_create.c ends here */
