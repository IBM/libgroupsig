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
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "sys/mem.h"
#include "misc/misc.h"
#include "kty04.h"
#include "groupsig/kty04/crl.h"
#include "groupsig/kty04/trapdoor.h"

/* Private functions */
static int _is_supported_format(crl_format_t format) {
  
  uint32_t i;
  
  for(i=0; i<KTY04_SUPPORTED_CRL_FORMATS_N; i++) {
    if(format == KTY04_SUPPORTED_CRL_FORMATS[i]) return 1;
  }
  
  return 0;
  
}

static kty04_crl_entry_t* _crl_entry_import_file(FILE *fd, crl_format_t format,
						 uint8_t *eof) {

  kty04_crl_entry_t *entry;
  char *line, *sid, *strapdoor;
  int rc;
    
  if(!fd || !eof) {
    LOG_EINVAL(&logger, __FILE__, "_crl_entry_import_file",
 	       __LINE__, LOGERROR);
    return NULL;
  }

  entry = NULL; line = NULL; sid = NULL; strapdoor = NULL;
  rc = IOK;

  /* Read until the next '\n': this function is crafted to read entries converted
     using crl_entry_to_string, so we know lines will end that way. If that changes,
     this function should be adapted consequently. */
  line = NULL;
  if(misc_read_file_line(fd, &line) == IERROR) {
    return NULL;
  }

  /* Check if we have reached EOF */
  if(feof(fd)) {
    *eof = 1;
    if(line) { free(line); line = NULL; }
    return NULL;
  }

  /* To be on the safe side, we make sid and strapdoor as long as line */
  if(!(sid = (char *) malloc(sizeof(char)*strlen(line)+1))) {
    LOG_ERRORCODE(&logger, __FILE__, "_crl_entry_import_file", __LINE__,
		  errno, LOGERROR);
    GOTOENDRC(IERROR, _crl_entry_import_file);
  }
  memset(sid, 0, strlen(line)+1);

  if(!(strapdoor = (char *) malloc(sizeof(char)*strlen(line)+1))) {
    LOG_ERRORCODE(&logger, __FILE__, "_crl_entry_import_file", __LINE__,
		  errno, LOGERROR);
    GOTOENDRC(IERROR, _crl_entry_import_file);
  }
  memset(strapdoor, 0, strlen(line)+1);

  /* The lines have the format "<id>\t<trapdoor>" */
  if((rc = sscanf(line, "%s\t%s", sid, strapdoor)) == EOF) {
    LOG_ERRORCODE(&logger, __FILE__, "_crl_entry_import_file", __LINE__,
		  errno, LOGERROR);
    GOTOENDRC(IERROR, _crl_entry_import_file);
  }

  if(rc != 2) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_crl_entry_import_file", __LINE__,
		      EDQUOT, "Corrupted CRL file.", LOGERROR);
    GOTOENDRC(IERROR, _crl_entry_import_file);
  }

  /* Create the entry and fill it */
  if(!(entry = kty04_crl_entry_init()))
    GOTOENDRC(IERROR, _crl_entry_import_file);

  if(!(entry->id = kty04_identity_from_string(sid))) {
    GOTOENDRC(IERROR, _crl_entry_import_file);
  }
  
  if(bigz_set_str(entry->trapdoor, strapdoor, 10) == IERROR) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_crl_entry_import_file", __LINE__,
		      EDQUOT, "Corrupted CRL file.", LOGERROR);
    GOTOENDRC(IERROR, _crl_entry_import_file);
  }

 _crl_entry_import_file_end:

  if(line) { free(line); line = NULL; }
  if(sid) { free(sid); sid = NULL; }
  if(strapdoor) { free(strapdoor); strapdoor = NULL; }

  if(rc == IERROR) {
    if(entry) kty04_crl_entry_free(entry);
  }
  
  return entry;

}

static crl_t* _crl_import_file(char *filename) {

  crl_t *crl;
  kty04_crl_entry_t *entry;
  FILE *fd;
  uint8_t eof;

  if(!filename) {
    LOG_EINVAL(&logger, __FILE__, "_crl_import_file", __LINE__, LOGERROR);
    return NULL;
  }

  /* Open the file for reading... */
  if(!(fd = fopen(filename, "r") )) {
    LOG_ERRORCODE(&logger, __FILE__, "_crl_import_file", __LINE__, errno, LOGERROR);
    return NULL;
  }

  if(!(crl = kty04_crl_init())) {
    fclose(fd);
    return NULL;
  }
  
  /* Read the CRL entries */
  eof = 0;
  while(!eof) {
    
    /** @todo CRL entry type fixed to "string"  */
    /* Parse the next member key */

    eof = 0;

    /* We have an error if we receive NULL withouth reaching EOF */
    if(!(entry = _crl_entry_import_file(fd, CRL_FILE, &eof)) && !eof) {
      crl_free(crl);
      fclose(fd);
      return NULL;
    }
    
    /* If we got one, store it in the CRL structure */
    if(entry) {
      if(kty04_crl_insert(crl, entry) == IERROR) {
	crl_free(crl);
	fclose(fd);
	return NULL;
      }
    }

  }
  
  fclose(fd);

  return crl;

}

static int _crl_export_file(crl_t *crl, char *filename) {

  uint64_t i;
  FILE *fd;
  char *sentry;

  if(!crl || !filename) {
    LOG_EINVAL(&logger, __FILE__, "_crl_export_file", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(fd = fopen(filename, "w"))) {
    LOG_ERRORCODE(&logger, __FILE__, "_crl_export_file", __LINE__,
		  errno, LOGERROR);
    return IERROR;
  }

  /* Dump all the entries */
  /** @todo The entries are dumped just as "tabbed tostringed-numbers" (perhaps
      several formats should be supported)*/
  for(i=0; i<crl->n; i++) {
    if(!(sentry = kty04_crl_entry_to_string((kty04_crl_entry_t *) crl->entries[i]))) {
      fclose(fd); fd = NULL;
      return IERROR;
    }
    fprintf(fd, "%s\n", sentry);
    free(sentry); sentry = NULL;
  }

  fclose(fd); fd = NULL;

  return IOK;

}

/* Public functions */

/* entry functions  */

kty04_crl_entry_t* kty04_crl_entry_init() {
  
  kty04_crl_entry_t *entry;

  if(!(entry = (kty04_crl_entry_t *) malloc(sizeof(kty04_crl_entry_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_crl_entry_init", __LINE__,
		  errno, LOGERROR);
    return NULL;
  }

  if(!(entry->id = kty04_identity_init())) {
    free(entry); entry = NULL;
    return NULL;
  }

  if(!(entry->trapdoor = bigz_init())) {
    kty04_identity_free(entry->id);
    free(entry); entry = NULL;
    return NULL;
  }

  return entry;

}

int kty04_crl_entry_free(kty04_crl_entry_t *entry) {

  int rc;

  if(!entry) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_crl_entry_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  rc = IOK;
  
  rc += kty04_identity_free(entry->id);
  rc += bigz_free(entry->trapdoor);
  free(entry); entry = NULL;

  if(rc) rc = IERROR;
  
  return rc;

}

int kty04_crl_entry_cmp_id(void *entry1, void *entry2) {

  kty04_crl_entry_t *e1, *e2;
  identity_t *id1, *id2;
  kty04_identity_t *kty04_id1, *kty04_id2;

  if(!entry1 || !entry2) {
    LOG_EINVAL(&logger, __FILE__, "kty04_crl_entry_cmp_id", __LINE__, LOGERROR);
    return 0;
  }

  e1 = (kty04_crl_entry_t *) entry1;
  e2 = (kty04_crl_entry_t *) entry2;

  id1 = e1->id;
  id2 = e2->id;

  if(id1->scheme != GROUPSIG_KTY04_CODE || id2->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_crl_entry_cmp_id", __LINE__, LOGERROR);
    return 0;    
  }

  kty04_id1 = ((kty04_identity_t *) id1->id);
  kty04_id2 = ((kty04_identity_t *) id2->id);

  if(*kty04_id1 != *kty04_id2) return 0;

  return 1;

}

int kty04_crl_entry_cmp_trapdoors(void *entry1, void *entry2) {

  kty04_crl_entry_t *e1, *e2;

  if(!entry1 || !entry2) {
    LOG_EINVAL(&logger, __FILE__, "kty04_crl_entry_cmp_trapdoors", __LINE__, LOGERROR);
    return 0;
  }

  e1 = (kty04_crl_entry_t *) entry1;
  e2 = (kty04_crl_entry_t *) entry2;

  return bigz_cmp(e1->trapdoor, e2->trapdoor);

}

char* kty04_crl_entry_to_string(kty04_crl_entry_t *entry) {

  char *strapdoor, *sid, *sentry;
  uint64_t sentry_len;

  if(!entry) {
    LOG_EINVAL(&logger, __FILE__, "kty04_crl_entry_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  /* Get the string representations of the entry's fields */
  if(!(sid = kty04_identity_to_string(entry->id))) {
    return NULL;
  }

  if(!(strapdoor = bigz_get_str(10, entry->trapdoor))) {
    free(sid); sid = NULL;
    return NULL;
  }

  /* Calculate the length of the entry, adding a tab and a \n */
  sentry_len = strlen(sid)+strlen(strapdoor)+strlen("\t\n");

  if(!(sentry = (char *) malloc(sizeof(char)*sentry_len+1))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_crl_entry_to_string", __LINE__, errno,
		  LOGERROR);
    free(strapdoor); strapdoor = NULL;
    free(sid); sid = NULL;
    return NULL;
  }

  memset(sentry, 0, sentry_len*sizeof(char));
  sprintf(sentry, "%s\t%s", sid, strapdoor);

  mem_free(sid);
  mem_free(strapdoor);

  return sentry;
 
}

/* list functions */

crl_t* kty04_crl_init() {

  crl_t *crl;

  if(!(crl = (crl_t *) malloc(sizeof(crl_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_crl_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  crl->scheme = GROUPSIG_KTY04_CODE;
  crl->entries = NULL;
  crl->n = 0;

  return crl;

}

int kty04_crl_free(crl_t *crl) {
 
  uint64_t i;

  if(!crl || crl->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_crl_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  for(i=0; i<crl->n; i++) {
    kty04_crl_entry_free(crl->entries[i]);
  }

  mem_free(crl->entries); crl->entries = NULL;
  mem_free(crl);

  return IOK;

}

int kty04_crl_insert(crl_t *crl, void *entry) {

  if(!crl || crl->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_crl_insert", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!kty04_crl_entry_exists(crl, entry)) {

    if(!(crl->entries = (void **) 
	 realloc(crl->entries, sizeof(kty04_crl_entry_t *)*(crl->n+1)))) {
      LOG_ERRORCODE(&logger, __FILE__, "kty04_crl_insert", __LINE__, errno, LOGERROR);
      return IERROR;
    }

    crl->entries[crl->n] = entry;
    crl->n++;

  }

  return IOK;

}

int kty04_crl_remove(crl_t *crl, uint64_t index) {

  if(!crl  || crl->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_crl_remove", __LINE__, LOGERROR);
    return IERROR;
  }

  if(index >= crl->n) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_crl_remove", __LINE__, "Invalid index.",
  		   LOGERROR);
    return IERROR;
  }

  /* Just set it to NULL */
  /** @todo This will generate a lot of unused memory! Use some other ADT */
  crl->entries[index] = NULL;
  
  /* Decrement the number of entries */
  crl->n--;

  return IOK;

}

void* kty04_crl_get(crl_t *crl, uint64_t index) {

  if(!crl || crl->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_crl_get", __LINE__, LOGERROR);
    return NULL;
  }

  if(index >= crl->n) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_crl_get", __LINE__, "Invalid index.",
  		   LOGERROR);
    return NULL;
  }

  return crl->entries[index];
  
}

crl_t* kty04_crl_import(crl_format_t format, void *src) {

  if(!src) {
    LOG_EINVAL(&logger, __FILE__, "kty04_crl_import", __LINE__, LOGERROR);
    return NULL;
  }

  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_crl_import", __LINE__,
		   "Unsupported CRL type.", LOGERROR);
    return NULL;
  }

  /* If the received source is empty, means that we have to
     return an empty (new) CRL */

  switch(format) {
  case CRL_FILE:
    return _crl_import_file((char *) src);
  default:
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_crl_import", __LINE__,
		   "Unsupported CRL format.", LOGERROR);
    return NULL;
  }

  return NULL;
 
}

int kty04_crl_export(crl_t *crl, void *dst, crl_format_t format) {

  if(!crl || crl->scheme != GROUPSIG_KTY04_CODE ||
     !dst) {
    LOG_EINVAL(&logger, __FILE__, "kty04_crl_export", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_crl_export", __LINE__,
		   "Unsupported CRL format.", LOGERROR);
    return IERROR;
  }

  switch(format) {
  case CRL_FILE:
    return _crl_export_file(crl, (char *) dst);
  default:
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_crl_export", __LINE__,
		   "Unsupported CRL format.", LOGERROR);
    return IERROR;
  }

  return IERROR;

}

int kty04_crl_entry_exists(crl_t *crl, void *entry) {

  uint64_t i;
  int cmp;

  if(!crl || crl->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_crl_entry_exists", __LINE__, LOGERROR);
    return IERROR;
  }
  
  for(i=0; i<crl->n; i++) {

    errno = 0;
    cmp = kty04_crl_entry_cmp_trapdoors(entry, crl->entries[i]);
    if(errno) {
      return INT_MAX;
    }

    if(!cmp) return 1;

  }

  return 0;

}

int kty04_crl_trapdoor_exists(crl_t *crl, trapdoor_t *trap) {

  kty04_crl_entry_t *entry;
  int exists;

  if(!crl || crl->scheme != GROUPSIG_KTY04_CODE ||
     !trap || trap->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_crl_entry_exists", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(entry = kty04_crl_entry_init())) {
    return IERROR;
  }

  if(bigz_set(entry->trapdoor, *(kty04_trapdoor_t *) trap->trap) == IERROR) {
    return IERROR;
  }

  exists = kty04_crl_entry_exists(crl, entry);
  kty04_crl_entry_free(entry); entry = NULL;

  return exists;  

}

/*************************************************************************************/


/* /\* Private functions *\/ */
/* static int _is_supported_type(crl_type_t type) { */

/*   uint32_t i; */

/*   for(i=0; i<SUPPORTED_CRL_TYPES_N; i++) { */
/*     if(type == SUPPORTED_CRL_TYPES[i]) return 1; */
/*   } */

/*   return 0; */

/* } */

/* static int _crl_export_file(crl_t *crl, char *filename) { */

/*   uint64_t i; */
/*   char *strapdoor; */
/*   FILE *fd; */

/*   if(!crl || !filename) { */
/*     LOG_EINVAL(&logger, __FILE__, "_crl_export_file", __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */
  
/*   /\** @todo Differentiate between new databases and already created ones to */
/*       avoid re-writing everything! *\/ */
/*   if(!(fd = fopen(filename, "w"))) { */
/*     LOG_ERRORCODE(&logger, __FILE__, "_crl_export_file", __LINE__, errno, LOGERROR); */
/*     return IERROR; */
/*   } */
  
/*   /\* For now, we just print, for each entry in the crl, its index and trapdoor, */
/*    in the same line, separated by a space. *\/ */
/*   /\** @todo When doing this seriously, we should also write the ID of the CRL */
/*     issuer, the signature, etc... *\/ */

/*   /\* Print entries *\/ */
/*   for(i=0; i<crl->n; i++) { */

/*     if(!(strapdoor = bigz_get_str(10, ((kty04_crl_entry_t *)crl->entries[i])->trapdoor))) { */
/*       fclose(fd); */
/*       return IERROR; */
/*     } */

/*     fprintf(fd, "%lu %s\n", ((kty04_crl_entry_t *)crl->entries[i])->index, strapdoor); */
/*     free(strapdoor); strapdoor = NULL; */

/*   } */

/*   fclose(fd); */

/*   return IOK; */

/* } */

/* int _crl_append_entry_export_file(kty04_crl_entry_t *entry, char *filename) { */

/*   FILE *fd; */
/*   char *strapdoor; */

/*   if(!entry || !filename) { */
/*     LOG_EINVAL(&logger, __FILE__, "_crl_append_entry_export_file", __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   if(!(fd = fopen(filename, "a"))) { */
/*     LOG_ERRORCODE(&logger, __FILE__, "_crl_append_entry_export_file", __LINE__, errno, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   /\* For now, we just print, for each entry in the crl, its index and trapdoor, */
/*    in the same line, separated by a space. *\/ */
/*   /\** @todo When doing this seriously, we should also write the ID of the CRL */
/*     issuer, the signature, etc... *\/ */

/*   if(!(strapdoor = bigz_get_str(10, entry->trapdoor))) { */
/*     fclose(fd); */
/*     return IERROR; */
/*   } */
  
/*   fprintf(fd, "%lu %s\n", entry->index, strapdoor); */
/*   free(strapdoor); strapdoor = NULL;    */

/*   fclose(fd); */

/*   return IOK; */

/* } */

/* static crl_t* _crl_import_file(char *filename) {  */

/*   bigz_t trapdoor; */
/*   uint64_t i, index; */
/*   crl_t *crl; */
/*   char *line, *sindex, *strapdoor; */
/*   FILE *fd; */
/*   int rc; */
/*   uint8_t eof; */

/*   if(!filename) { */
/*     LOG_EINVAL(&logger, __FILE__, "_crl_import_file", __LINE__, LOGERROR); */
/*     return NULL; */
/*   } */

/*   line=NULL; sindex=NULL; strapdoor=NULL; trapdoor=NULL; fd=NULL; i=0; */
/*   rc = IOK; */
/*   crl = NULL; */

/*   if(!(fd = fopen(filename, "r"))) { */
/*     LOG_ERRORCODE(&logger, __FILE__, "_crl_import_file", __LINE__,  */
/* 		  errno, LOGERROR); */
/*     return NULL; */
/*   } */

/*   /\* Initialize the CRL *\/ */
/*   if(!(crl = crl_init())) GOTOENDRC(IERROR, _crl_import_file); */
 
/*   if(!(trapdoor = bigz_init())) { */
/*     GOTOENDRC(IERROR, _crl_import_file); */
/*   } */

/*   /\* Read each entry *\/ */
/*   eof = 0;  */
/*   while(!eof) { */
/*   /\* for(i=0; i<n; i++) { *\/ */
        
/*     free(line); line = NULL; */
/*     if(misc_read_file_line(fd, &line) == IERROR) { */
/*       GOTOENDRC(IERROR, _crl_import_file); */
/*     } */

/*     if(feof(fd)) { */
/*       /\* EOF and nothing read: break *\/ */
/*       if(!line || !strlen(line)) break; */
/*       eof = 1; /\* Something read, keep going *\/ */
/*     } */

/*     /\* We make the auxiliar variables sindex and strapdoor be the same length */
/*        as line, hence, the will always be big enough. *\/ */
/*     if(!(sindex = (char *) realloc(sindex, sizeof(char)*strlen(line)))) { */
/*       LOG_ERRORCODE(&logger, __FILE__, "_crl_import_file", __LINE__,  */
/* 		    errno, LOGERROR); */
/*       GOTOENDRC(IERROR, _crl_import_file); */
/*     } */

/*     memset(sindex, 0, strlen(line)); */

/*     if(!(strapdoor = (char *) realloc(strapdoor, sizeof(char)*strlen(line)))) { */
/*       LOG_ERRORCODE(&logger, __FILE__, "_crl_import_file", __LINE__,  */
/* 		    errno, LOGERROR); */
/*       GOTOENDRC(IERROR, _crl_import_file); */
/*     } */

/*     memset(strapdoor, 0, strlen(line)); */

/*     /\* The lines have the format "index trapdoor" *\/ */
/*     if((rc = sscanf(line, "%s %s", sindex, strapdoor)) == EOF) { */
/*       LOG_ERRORCODE(&logger, __FILE__, "_crl_import_file", __LINE__,  */
/* 		    errno, LOGERROR); */
/*       GOTOENDRC(IERROR, _crl_import_file); */
/*     } */

/*     if(rc != 2) { */
/*       LOG_ERRORCODE_MSG(&logger, __FILE__, "_crl_import_file", __LINE__,  */
/* 			EDQUOT, "Corrupted CRL file.", LOGERROR); */
/*       GOTOENDRC(IERROR, _crl_import_file); */
/*     } */

/*     /\* index is an uint64_t *\/ */
/*     errno = 0; */
/*     index = strtoul(sindex, NULL, 10); */
/*     if(errno) { */
/*       LOG_ERRORCODE(&logger, __FILE__, "_crl_import_file", __LINE__,  */
/* 		    errno, LOGERROR); */
/*       GOTOENDRC(IERROR, _crl_import_file); */
/*     } */

/*     /\* trapdoor is an mpz_t *\/ */
/*     if(bigz_set_str(trapdoor, strapdoor, 10) == -1) { */
/*       LOG_ERRORCODE(&logger, __FILE__, "_crl_import_file", __LINE__,  */
/* 		    errno, LOGERROR); */
/*       GOTOENDRC(IERROR, _crl_import_file); */
/*     } */

/*     /\* Increment the crl entries array size *\/    */
/*     if(!(crl->entries = (void **) realloc(crl->entries, sizeof(void *)*(++i)))) { */
/*       LOG_ERRORCODE(&logger, __FILE__, "_crl_import_file", __LINE__, errno, LOGERROR); */
/*       GOTOENDRC(IERROR, _crl_import_file); */
/*     } */

/*     /\* Initialize the new crl entry *\/ */
/*     if(!(crl->entries[i-1] = crl_entry_init())) { */
/*       LOG_ERRORCODE(&logger, __FILE__, "_crl_import_file", __LINE__,  */
/* 		    errno, LOGERROR); */
/*       GOTOENDRC(IERROR, _crl_import_file); */
/*     } */
    
/*     if(bigz_set(((kty04_crl_entry_t *)crl->entries[i-1])->trapdoor, trapdoor) == IERROR) { */
/*       LOG_ERRORCODE(&logger, __FILE__, "_crl_import_file", __LINE__,  */
/* 		    errno, LOGERROR); */
/*       GOTOENDRC(IERROR, _crl_import_file); */
/*     } */

/*     ((kty04_crl_entry_t *)crl->entries[i-1])->index = index; */
/*     crl->n = i; */
    
/*   } */

/*  _crl_import_file_end:   */

/*   if(line) { free(line); line = NULL; } */
/*   if(sindex) { free(sindex); sindex = NULL; } */
/*   if(strapdoor) { free(strapdoor); strapdoor = NULL; } */
/*   if(trapdoor) bigz_free(trapdoor); */
/*   if(fd) { fclose(fd); fd = NULL; } */

/*   if(crl) { */
/*     if(i != crl->n) { */
/*       LOG_ERRORCODE_MSG(&logger, __FILE__, "_crl_import_file", __LINE__, */
/* 			EDQUOT, "Corrupted CRL file.", LOGERROR); */
/*       free(crl); crl = NULL; */
/*       rc = IERROR; */
/*     } */
/*   } */

/*   return crl; */

/* } */

/* /\* Public functions *\/ */
/* crl_t* crl_init() { */

/*   crl_t *crl; */

/*   if(!(crl = (crl_t *) malloc(sizeof(crl_t)))) { */
/*     LOG_ERRORCODE(&logger, __FILE__, "crl_init", __LINE__, errno, LOGERROR); */
/*     return NULL; */
/*   } */

/*   crl->n = 0; */
/*   crl->entries = NULL; */

/*   return crl; */

/* } */

/* int crl_free(crl_t *crl) { */
  
/*   uint64_t i; */

/*   if(!crl) { */
/*     LOG_EINVAL_MSG(&logger, __FILE__, "crl_free", __LINE__,  */
/* 		   "Nothing to free.", LOGWARN); */
/*     return IOK; */
/*   } */

/*   if(crl->entries) { */
/*     for(i=0; i<crl->n; i++) { */
/*       crl_entry_free(crl->entries[i]); */
/*     }   */
/*     free(crl->entries); crl->entries = NULL; */
/*   } */

/*   free(crl); crl = NULL; */

/*   return IOK; */

/* } */

/* void* crl_entry_init() { */

/*   kty04_crl_entry_t *entry; */

/*   if(!(entry = (kty04_crl_entry_t *) malloc(sizeof(kty04_crl_entry_t)))) { */
/*     LOG_ERRORCODE(&logger, __FILE__, "crl_entry_init", __LINE__, errno, LOGERROR); */
/*     return NULL; */
/*   } */

/*   if(!(entry->trapdoor = bigz_init())) { */
/*     free(entry); entry = NULL; */
/*     return NULL; */
/*   } */
  
/*   entry->index = UINT64_MAX; */

/*   return entry; */

/* } */

/* int crl_entry_free(void *entry) { */

/*   if(!entry) { */
/*     LOG_EINVAL_MSG(&logger, __FILE__, "crl_entry_free", __LINE__,  */
/* 		   "Nothing to free.", LOGWARN); */
/*     return IOK; */
/*   } */

/*   bigz_free(((kty04_crl_entry_t *) entry)->trapdoor); */
/*   free(entry); entry = NULL; */
  
/*   return IOK; */
  
/* } */

/* int crl_insert(crl_t *crl, void *entry) { */

/*   uint64_t i; */

/*   if(!crl || !entry) { */
/*     LOG_EINVAL(&logger, __FILE__, "crl_insert", __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   /\** @todo A really good improvement will be to use hash tables, to make search */
/*       and update cost be O(1) instead O(N)... *\/ */
/*   for(i=0; i<crl->n; i++) { */
/*     if(((kty04_crl_entry_t *) crl->entries[i])->index == ((kty04_crl_entry_t *) entry)->index) { */
/*       return IEXISTS; */
/*     } */
/*   } */

/*   /\* Allocate space for a new entry in the entries array *\/ */
/*   if(!(crl->entries = (void **)  */
/*        realloc((void **) crl->entries, sizeof(void)*(crl->n+1)))) { */
/*     LOG_ERRORCODE(&logger, __FILE__, "crl_insert", __LINE__, errno, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   crl->entries[crl->n] = entry; */
/*   crl->n++; */
  
/*   return IOK; */

/* } */

/* void* crl_get(crl_t *crl, uint64_t index) { */

/*   if(!crl) { */
/*     LOG_EINVAL(&logger, __FILE__, "crl_get", __LINE__, LOGERROR); */
/*     return NULL; */
/*   } */

/*   if(index >= crl->n) { */
/*     LOG_ERRORCODE_MSG(&logger, __FILE__, "crl_get", __LINE__,  */
/* 		      EDQUOT, "Index out of range.", LOGERROR); */
/*     return NULL; */
/*   } */

/*   return crl->entries[index]; */

/* } */

/* int crl_remove(crl_t *crl, uint64_t index) { */

/*   if(!crl) { */
/*     LOG_EINVAL(&logger, __FILE__, "crl_get", __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   if(index >= crl->n) { */
/*     LOG_ERRORCODE_MSG(&logger, __FILE__, "crl_get", __LINE__,  */
/* 		      EDQUOT, "Index out of range.", LOGERROR); */
/*     return IERROR;     */
/*   } */

/*   /\** @todo CRL remove only deletes the entry, leaving a NULL pointer! *\/ */
/*   return crl_entry_free(crl->entries[index]); */

/* } */

/* crl_t* crl_import(void *src, crl_type_t type) {  */

/*   if(!src) { */
/*     LOG_EINVAL(&logger, __FILE__, "crl_import", __LINE__, LOGERROR); */
/*     return NULL; */
/*   } */

/*   if(!_is_supported_type(type)) { */
/*     LOG_EINVAL_MSG(&logger, __FILE__, "crl_import", __LINE__,  */
/* 		   "Unsupported CRL format.", LOGERROR); */
/*     return NULL; */
/*   } */

/*   switch(type) { */
/*   case CRL_FILE: */
/*     return _crl_import_file((char *) src); */
/*   default: */
/*     LOG_EINVAL_MSG(&logger, __FILE__, "crl_import", __LINE__,  */
/* 		   "Unsupported CRL format.", LOGERROR);     */
/*     return NULL; */
/*   } */

/*   return NULL; */

/* } */

/* int crl_export(crl_t *crl, crl_type_t type, void *dst) {  */

/*   if(!crl || !dst) { */
/*     LOG_EINVAL(&logger, __FILE__, "crl_export", __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   if(!_is_supported_type(type)) { */
/*     LOG_EINVAL_MSG(&logger, __FILE__, "crl_export", __LINE__,  */
/* 		   "Unsupported CRL format.", LOGERROR); */
/*     return IERROR; */
/*   } */

/*   switch(type) { */
/*   case CRL_FILE: */
/*     return _crl_export_file(crl, (char *) dst); */
/*   default: */
/*     LOG_EINVAL_MSG(&logger, __FILE__, "crl_export", __LINE__,  */
/* 		   "Unsupported CRL format.", LOGERROR);     */
/*     return IERROR; */
/*   } */

/*   return IERROR; */

/* } */

/* int crl_append_entry_export(kty04_crl_entry_t *entry, crl_type_t type, void *dst) { */

/*   if(!entry || !dst) { */
/*     LOG_EINVAL(&logger, __FILE__, "crl_append_entry_export", __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   if(!_is_supported_type(type)) { */
/*     LOG_EINVAL_MSG(&logger, __FILE__, "crl_append_entry_export", __LINE__,  */
/* 		   "Unsupported CRL format.", LOGERROR); */
/*     return IERROR; */
/*   } */

/*   switch(type) { */
/*   case CRL_FILE: */
/*     return _crl_append_entry_export_file(entry, (char *) dst); */
/*   default: */
/*     LOG_EINVAL_MSG(&logger, __FILE__, "crl_append_entry_export", __LINE__,  */
/* 		   "Unsupported CRL format.", LOGERROR);     */
/*     return IERROR; */
/*   } */

/*   return IERROR; */

/* } */

/* char* crl_to_string(crl_t *crl) { */

/*   uint64_t i, size, length, scur; */
/*   char *strap, *sindex, *scrl; */

/*   if(!crl) { */
/*     LOG_EINVAL(&logger, __FILE__, "crl_to_string", __LINE__, LOGERROR); */
/*     return NULL; */
/*   } */

/*   strap = NULL; sindex = NULL; scrl = NULL; */

/*   size = 0; length = 0; */
/*   for(i=0; i<crl->n; i++) { */

/*     sindex = misc_uint642string(((kty04_crl_entry_t *) crl->entries[i])->index); */
/*     strap = bigz_get_str(10, ((kty04_crl_entry_t *) crl->entries[i])->trapdoor); */

/*     if(!sindex || !strap) { */
/*       if(sindex) { free(sindex); sindex = NULL; } */
/*       if(strap) { free(strap); strap = NULL; } */
/*       free(scrl); scrl = NULL; */
/*       return NULL; */
/*     } */

/*     scur = strlen(sindex)+strlen("\tindex: \n")+ */
/*       strlen(strap)+strlen("\ttrapdoor: \n"); */
    
/*     size += scur; */

/*     if(!(scrl = (char *) realloc((char*) scrl, sizeof(char)*(size+1)))) { */
/*       free(sindex); sindex = NULL; */
/*       free(strap); strap = NULL; */
/*       return NULL; */
/*     } */

/*     sprintf(scrl, "\tindex: %s\n\ttrapdoor: %s\n", sindex, strap); */
/*     length += scur; */

/*     /\* Trailing '\0' *\/ */
/*     scrl[length] = 0; */
    
/*     free(sindex); sindex = NULL; */
/*     free(strap); strap = NULL; */

/*   }  */

/*   return scrl; */

/* } */

/* kty04_crl.c ends here */
