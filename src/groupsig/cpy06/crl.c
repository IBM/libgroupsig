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
#include "cpy06.h"
#include "groupsig/cpy06/crl.h"
#include "groupsig/cpy06/trapdoor.h"

/* Private functions */
static int _is_supported_format(crl_format_t format) {
  
  uint32_t i;
  
  for(i=0; i<CPY06_SUPPORTED_CRL_FORMATS_N; i++) {
    if(format == CPY06_SUPPORTED_CRL_FORMATS[i]) return 1;
  }
  
  return 0;
  
}

static cpy06_crl_entry_t* _crl_entry_import_file(FILE *fd, crl_format_t format,
						 uint8_t *eof) {

  cpy06_crl_entry_t *entry;
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
  if((rc = sscanf(line, "%s\t%[^\n]", sid, strapdoor)) == EOF) {
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
  if(!(entry = cpy06_crl_entry_init()))
    GOTOENDRC(IERROR, _crl_entry_import_file);

  if(!(entry->id = cpy06_identity_from_string(sid))) {
    GOTOENDRC(IERROR, _crl_entry_import_file);
  }
  
  if(!(entry->trapdoor = cpy06_trapdoor_from_string(strapdoor))) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_crl_entry_import_file", __LINE__,
		      EDQUOT, "Corrupted CRL file.", LOGERROR);
    identity_free(entry->id); entry->id = NULL;
    GOTOENDRC(IERROR, _crl_entry_import_file);
  }

 _crl_entry_import_file_end:

  if(line) { free(line); line = NULL; }
  if(sid) { free(sid); sid = NULL; }
  if(strapdoor) { free(strapdoor); strapdoor = NULL; }

  if(rc == IERROR) {
    if(entry) cpy06_crl_entry_free(entry);
  }
  
  return entry;

}

static crl_t* _crl_import_file(char *filename) {

  crl_t *crl;
  cpy06_crl_entry_t *entry;
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

  if(!(crl = cpy06_crl_init())) {
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
      if(cpy06_crl_insert(crl, entry) == IERROR) {
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
    if(!(sentry = cpy06_crl_entry_to_string((cpy06_crl_entry_t *) crl->entries[i]))) {
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

cpy06_crl_entry_t* cpy06_crl_entry_init() {
 
  cpy06_crl_entry_t *entry;

  if(!(entry = (cpy06_crl_entry_t *) malloc(sizeof(cpy06_crl_entry_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "cpy06_crl_entry_init", __LINE__,
		  errno, LOGERROR);
    return NULL;
  }

  if(!(entry->id = identity_init(GROUPSIG_CPY06_CODE))) {
    identity_free(entry->id); entry->id = NULL;
    mem_free(entry); entry = NULL;
    return NULL;
  }

  if(!(entry->trapdoor = trapdoor_init(GROUPSIG_CPY06_CODE))) {
    identity_free(entry->id); entry->id = NULL;
    mem_free(entry); entry = NULL;
    return NULL;
  }

  return entry;

}

int cpy06_crl_entry_free(cpy06_crl_entry_t *entry) {

  int rc;

  if(!entry) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_crl_entry_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  rc = IOK;
  
  rc += cpy06_identity_free(entry->id);
  rc += cpy06_trapdoor_free(entry->trapdoor);
  free(entry); entry = NULL;

  if(rc) rc = IERROR;
  
  return rc;

}

int cpy06_crl_entry_cmp_id(void *entry1, void *entry2) {

  cpy06_crl_entry_t *e1, *e2;
  identity_t *id1, *id2;
  cpy06_identity_t *cpy06_id1, *cpy06_id2;

  if(!entry1 || !entry2) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_crl_entry_cmp_id", __LINE__, LOGERROR);
    return 0;
  }

  e1 = (cpy06_crl_entry_t *) entry1;
  e2 = (cpy06_crl_entry_t *) entry2;

  id1 = e1->id;
  id2 = e2->id;

  if(id1->scheme != GROUPSIG_CPY06_CODE || id2->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_crl_entry_cmp_id", __LINE__, LOGERROR);
    return 0;    
  }

  cpy06_id1 = ((cpy06_identity_t *) id1->id);
  cpy06_id2 = ((cpy06_identity_t *) id2->id);

  if(*cpy06_id1 != *cpy06_id2) return 0;

  return 1;

}

int cpy06_crl_entry_cmp_trapdoors(void *entry1, void *entry2) {

  cpy06_crl_entry_t *e1, *e2;

  if(!entry1 || !entry2) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_crl_entry_cmp_trapdoors", __LINE__, LOGERROR);
    return 0;
  }

  e1 = (cpy06_crl_entry_t *) entry1;
  e2 = (cpy06_crl_entry_t *) entry2;

  return element_cmp(((cpy06_trapdoor_t *) e1->trapdoor->trap)->open, 
		     ((cpy06_trapdoor_t *) e2->trapdoor->trap)->open);

}

char* cpy06_crl_entry_to_string(cpy06_crl_entry_t *entry) {

  char *strapdoor, *sid, *sentry;
  uint64_t sentry_len;

  if(!entry) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_crl_entry_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  /* Get the string representations of the entry's fields */
  if(!(sid = cpy06_identity_to_string(entry->id))) {
    return NULL;
  }

  if(!(strapdoor = cpy06_trapdoor_to_string(entry->trapdoor))) {
    free(sid); sid = NULL;
    return NULL;
  }

  /* Calculate the length of the entry, adding a tab and a \n */
  sentry_len = strlen(sid)+strlen(strapdoor)+strlen("\t\n");

  if(!(sentry = (char *) malloc(sizeof(char)*sentry_len+1))) {
    LOG_ERRORCODE(&logger, __FILE__, "cpy06_crl_entry_to_string", __LINE__, errno,
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

crl_t* cpy06_crl_init() {

  crl_t *crl;

  if(!(crl = (crl_t *) malloc(sizeof(crl_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "cpy06_crl_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  crl->scheme = GROUPSIG_CPY06_CODE;
  crl->entries = NULL;
  crl->n = 0;

  return crl;

}

int cpy06_crl_free(crl_t *crl) {
 
  uint64_t i;

  if(!crl || crl->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_crl_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  for(i=0; i<crl->n; i++) {
    cpy06_crl_entry_free(crl->entries[i]);
  }

  mem_free(crl->entries); crl->entries = NULL;
  mem_free(crl);

  return IOK;

}

int cpy06_crl_insert(crl_t *crl, void *entry) {

  if(!crl || crl->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_crl_insert", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!cpy06_crl_entry_exists(crl, entry)) {

    if(!(crl->entries = (void **) 
	 realloc(crl->entries, sizeof(cpy06_crl_entry_t *)*(crl->n+1)))) {
      LOG_ERRORCODE(&logger, __FILE__, "cpy06_crl_insert", __LINE__, errno, LOGERROR);
      return IERROR;
    }

    crl->entries[crl->n] = entry;
    crl->n++;

  }

  return IOK;

}

int cpy06_crl_remove(crl_t *crl, uint64_t index) {

  if(!crl  || crl->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_crl_remove", __LINE__, LOGERROR);
    return IERROR;
  }

  if(index >= crl->n) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_crl_remove", __LINE__, "Invalid index.",
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

void* cpy06_crl_get(crl_t *crl, uint64_t index) {

  if(!crl || crl->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_crl_get", __LINE__, LOGERROR);
    return NULL;
  }

  if(index >= crl->n) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_crl_get", __LINE__, "Invalid index.",
  		   LOGERROR);
    return NULL;
  }

  return crl->entries[index];
  
}

crl_t* cpy06_crl_import(crl_format_t format, void *src) {

  if(!src) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_crl_import", __LINE__, LOGERROR);
    return NULL;
  }

  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_crl_import", __LINE__,
		   "Unsupported CRL type.", LOGERROR);
    return NULL;
  }

  /* If the received source is empty, means that we have to
     return an empty (new) CRL */

  switch(format) {
  case CRL_FILE:
    return _crl_import_file((char *) src);
  default:
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_crl_import", __LINE__,
		   "Unsupported CRL format.", LOGERROR);
    return NULL;
  }

  return NULL;
 
}

int cpy06_crl_export(crl_t *crl, void *dst, crl_format_t format) {

  if(!crl || crl->scheme != GROUPSIG_CPY06_CODE ||
     !dst) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_crl_export", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_crl_export", __LINE__,
		   "Unsupported CRL format.", LOGERROR);
    return IERROR;
  }

  switch(format) {
  case CRL_FILE:
    return _crl_export_file(crl, (char *) dst);
  default:
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_crl_export", __LINE__,
		   "Unsupported CRL format.", LOGERROR);
    return IERROR;
  }

  return IERROR;

}

int cpy06_crl_entry_exists(crl_t *crl, void *entry) {

  uint64_t i;
  int cmp;

  if(!crl || crl->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_crl_entry_exists", __LINE__, LOGERROR);
    return IERROR;
  }
  
  for(i=0; i<crl->n; i++) {

    errno = 0;
    cmp = cpy06_crl_entry_cmp_trapdoors(entry, crl->entries[i]);
    if(errno) {
      return INT_MAX;
    }

    if(!cmp) return 1;

  }

  return 0;

}

int cpy06_crl_trapdoor_exists(crl_t *crl, trapdoor_t *trap) {

  cpy06_crl_entry_t *entry;
  int exists;

  if(!crl || crl->scheme != GROUPSIG_CPY06_CODE ||
     !trap || trap->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_crl_entry_exists", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(entry = cpy06_crl_entry_init())) {
    return IERROR;
  }

  element_init_Zr(((cpy06_trapdoor_t *) entry->trapdoor->trap)->open,
		  ((cpy06_sysenv_t *) sysenv->data)->pairing);
  element_set(((cpy06_trapdoor_t *) entry->trapdoor->trap)->open, 
	      ((cpy06_trapdoor_t *) trap->trap)->open);

  exists = cpy06_crl_entry_exists(crl, entry);
  cpy06_crl_entry_free(entry); entry = NULL;

  return exists;  

}

/* cpy06_crl.c ends here */
