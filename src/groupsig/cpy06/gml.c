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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "misc/misc.h"
#include "sys/mem.h"
#include "cpy06.h"
#include "groupsig/cpy06/gml.h"
#include "groupsig/cpy06/identity.h"
#include "groupsig/cpy06/trapdoor.h"

/* Private functions */
static int _is_supported_format(gml_format_t format) {
  
  uint32_t i;
  
  for(i=0; i<CPY06_SUPPORTED_GML_FORMATS_N; i++) {
    if(format == CPY06_SUPPORTED_GML_FORMATS[i]) return 1;
  }
  
  return 0;
  
}

static cpy06_gml_entry_t* _gml_entry_import_file(FILE *fd, gml_format_t format,
						 uint8_t *eof) {

  /* identity_t *id; */
  /* trapdoor_t *trap; */
  cpy06_gml_entry_t *entry;
  char *line, *sid, *strapdoor;
  int rc;
    
  if(!fd || !eof) {
    LOG_EINVAL(&logger, __FILE__, "_gml_entry_import_file",
 	       __LINE__, LOGERROR);
    return NULL;
  }

  entry = NULL; line = NULL; strapdoor = NULL;
  rc = IOK;

  /* Read until the next '\n': this function is crafted to read entries converted
     using gml_entry_to_string, so we know lines will end that way. If that changes,
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
    LOG_ERRORCODE(&logger, __FILE__, "_gml_entry_import_file", __LINE__,
		  errno, LOGERROR);
    GOTOENDRC(IERROR, _gml_entry_import_file);
  }
  memset(sid, 0, strlen(line)+1);

  if(!(strapdoor = (char *) malloc(sizeof(char)*strlen(line)+1))) {
    LOG_ERRORCODE(&logger, __FILE__, "_gml_entry_import_file", __LINE__,
		  errno, LOGERROR);
    GOTOENDRC(IERROR, _gml_entry_import_file);
  }
  memset(strapdoor, 0, strlen(line)+1);

  /* The lines have the format "<id>\t<trapdoor>" */
  if((rc = sscanf(line, "%s\t%[^\n]", sid, strapdoor)) == EOF) {
    LOG_ERRORCODE(&logger, __FILE__, "_gml_entry_import_file", __LINE__,
		  errno, LOGERROR);
    GOTOENDRC(IERROR, _gml_entry_import_file);
  }

  if(rc != 2) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_gml_entry_import_file", __LINE__,
		      EDQUOT, "Corrupted GML file.", LOGERROR);
    GOTOENDRC(IERROR, _gml_entry_import_file);
  }

  /* Create the entry and fill it */
  if(!(entry = cpy06_gml_entry_init()))
    GOTOENDRC(IERROR, _gml_entry_import_file);
  
  if(!(entry->id = identity_from_string(GROUPSIG_CPY06_CODE, sid))) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_gml_entry_import_file", __LINE__,
		      EDQUOT, "Corrupted GML file.", LOGERROR);
    GOTOENDRC(IERROR, _gml_entry_import_file);    
  }
  
  /* if(cpy06_identity_copy(entry->id, id) == IERROR) { */
  /*   identity_free(id); id = NULL; */
  /*   GOTOENDRC(IERROR, _gml_entry_import_file); */
  /* } */

  /* identity_free(id); id = NULL; */

  if(!(entry->trapdoor = cpy06_trapdoor_from_string(strapdoor))) {
    identity_free(entry->id); entry->id = NULL;
    GOTOENDRC(IERROR, _gml_entry_import_file);
  }

  /* if(cpy06_trapdoor_copy(entry->trapdoor, trap) == IERROR) { */
  /*   identity_free(id); id = NULL; */
  /*   trapdoor_free(trap); trap = NULL; */
  /*   GOTOENDRC(IERROR, _gml_entry_import_file); */
  /* } */

  /* trapdoor_free(trap); trap = NULL; */

 _gml_entry_import_file_end:

  if(line) { mem_free(line); line = NULL; }
  if(sid) { mem_free(sid); sid = NULL; }
  if(strapdoor) { free(strapdoor); strapdoor = NULL; }

  if(rc == IERROR) {
    if(entry) cpy06_gml_entry_free(entry);
  }
  
  return entry;

}

static gml_t* _gml_import_file(char *filename) {

  gml_t *gml;
  cpy06_gml_entry_t *entry;
  FILE *fd;
  uint8_t eof;

  if(!filename) {
    LOG_EINVAL(&logger, __FILE__, "_gml_import_file", __LINE__, LOGERROR);
    return NULL;
  }

  /* Open the file for reading... */
  if(!(fd = fopen(filename, "r") )) {
    LOG_ERRORCODE(&logger, __FILE__, "_gml_import_file", __LINE__, errno, LOGERROR);
    return NULL;
  }

  if(!(gml = cpy06_gml_init())) {
    fclose(fd);
    return NULL;
  }
  
  /* Read the GML entries */
  eof = 0;
  while(!eof) {
    
    /** @todo GML entry type fixed to "string"  */
    /* Parse the next member key */

    eof = 0;

    /* We have an error if we receive NULL withouth reaching EOF */
    if(!(entry = _gml_entry_import_file(fd, GML_FILE, &eof)) && !eof) {
      gml_free(gml);
      fclose(fd);
      return NULL;
    }
    
    /* If we got one, store it in the GML structure */
    if(entry) {

      if(gml_insert(gml,entry) == IERROR) {
	gml_free(gml);
	fclose(fd);
	return NULL;
      }
    }

  }
  
  fclose(fd);

  return gml;

}

static int _gml_export_new_entry_file(cpy06_gml_entry_t *entry, char *filename) {

  FILE *fd;
  char *sentry;

  if(!entry || !filename) {
    LOG_EINVAL(&logger, __FILE__, "_gml_export_new_entry_file", __LINE__, LOGERROR);
    return IERROR;
  }
  
  if(!(fd = fopen(filename, "a"))) {
    LOG_ERRORCODE(&logger, __FILE__, "_gml_export_new_entry_file", __LINE__, errno, LOGERROR);
    return IERROR;
  }
  
  if(!(sentry = cpy06_gml_entry_to_string(entry))) {
    fclose(fd); fd = NULL;
    return IERROR;
  }

  fprintf(fd, "%s\n", sentry);
  free(sentry); sentry = NULL;

  fclose(fd);

  return IOK;

}

static int _gml_export_file(gml_t *gml, char *filename) {

  uint64_t i;
  FILE *fd;
  char *sentry;

  if(!gml || !filename) {
    LOG_EINVAL(&logger, __FILE__, "_gml_export_file", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(fd = fopen(filename, "w"))) {
    LOG_ERRORCODE(&logger, __FILE__, "_gml_export_file", __LINE__,
		  errno, LOGERROR);
    return IERROR;
  }

  /* Dump all the entries */
  /** @todo The entries are dumped just as "tabbed tostringed-numbers" (perhaps
      several formats should be supported)*/
  for(i=0; i<gml->n; i++) {
    if(!(sentry = cpy06_gml_entry_to_string((cpy06_gml_entry_t *) gml->entries[i]))) {
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

cpy06_gml_entry_t* cpy06_gml_entry_init() {

  cpy06_gml_entry_t *entry;

  if(!(entry = (cpy06_gml_entry_t *) malloc(sizeof(cpy06_gml_entry_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "cpy06_gml_entry_init", __LINE__,
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


int cpy06_gml_entry_free(cpy06_gml_entry_t *entry) {

  if(!entry) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_gml_entry_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if(entry->id) { identity_free(entry->id); entry->id = NULL; }
  if(entry->trapdoor) { trapdoor_free(entry->trapdoor); entry->trapdoor = NULL; }
  mem_free(entry);
  
  return IOK;

}

int cpy06_gml_entry_cmp_trapdoors(cpy06_gml_entry_t *entry1, cpy06_gml_entry_t *entry2) {

  if(!entry1 || !entry2) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_gml_entry_cmp_trapdoors", __LINE__, LOGERROR);
    return 0;
  }

  return cpy06_trapdoor_cmp(entry1->trapdoor, entry2->trapdoor);

}

char* cpy06_gml_entry_to_string(cpy06_gml_entry_t *entry) {

  char *strapdoor, *sid, *sentry;
  uint64_t sentry_len;

  if(!entry) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_gml_entry_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  /* A string representation of a GML entry will be: 
     <id>\t<trapdoor> */

  /* Get the string representations of the entry's fields */
  if(!(sid = identity_to_string(entry->id))) {
    return NULL;
  }

  if(!(strapdoor = trapdoor_to_string(entry->trapdoor))) {
    mem_free(sid); sid = NULL;
    return NULL;
  }

  /* Calculate the length of the entry, adding a tab and a \n */
  sentry_len = strlen(sid)+strlen(strapdoor)+strlen("\t");

  if(!(sentry = (char *) malloc(sizeof(char)*sentry_len+1))) {
    LOG_ERRORCODE(&logger, __FILE__, "cpy06_gml_entry_to_string", __LINE__, errno,
		  LOGERROR);
    free(strapdoor); strapdoor = NULL;
    mem_free(sid); sid = NULL;
    return NULL;
  }

  memset(sentry, 0, sentry_len*sizeof(char));
  sprintf(sentry, "%s\t%s", sid, strapdoor);

  mem_free(sid); sid = NULL;
  mem_free(strapdoor); strapdoor = NULL;

  return sentry;
 
}

/* list functions */

gml_t* cpy06_gml_init() {

  gml_t *gml;

  if(!(gml = (gml_t *) malloc(sizeof(gml_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "cpy06_gml_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  gml->scheme = GROUPSIG_CPY06_CODE;
  gml->entries = NULL;
  gml->n = 0;

  return gml;

}

int cpy06_gml_free(gml_t *gml) {

  uint64_t i;

  if(!gml || gml->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_gml_free", __LINE__,
  		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  for(i=0; i<gml->n; i++) {
    cpy06_gml_entry_free(gml->entries[i]);
  }

  mem_free(gml->entries); gml->entries = NULL;
  mem_free(gml);

  return IOK;

}

int cpy06_gml_insert(gml_t *gml, void *entry) {

  if(!gml || gml->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_gml_insert", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(gml->entries = (void **) 
       realloc(gml->entries, sizeof(cpy06_gml_entry_t *)*(gml->n+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "cpy06_gml_insert", __LINE__, errno, LOGERROR);
    return IERROR;
  }

  gml->entries[gml->n] = entry;
  gml->n++;

  return IOK;

}

int cpy06_gml_remove(gml_t *gml, uint64_t index) {

  if(!gml || gml->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_gml_remove", __LINE__, LOGERROR);
    return IERROR;
  }

  if(index >= gml->n) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_gml_remove", __LINE__, "Invalid index.",
  		   LOGERROR);
    return IERROR;
  }

  /* Just set it to NULL */
  /** @todo This will generate a lot of unused memory! Use some other ADT */
  gml->entries[index] = NULL;
  
  /* Decrement the number of entries */
  gml->n--;

  return IOK;

}

void* cpy06_gml_get(gml_t *gml, uint64_t index) {

  if(!gml || gml->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_gml_get", __LINE__, LOGERROR);
    return NULL;
  }

  if(index >= gml->n) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_gml_get", __LINE__, "Invalid index.",
  		   LOGERROR);
    return NULL;
  }

  return gml->entries[index];
  
}

gml_t* cpy06_gml_import(gml_format_t format, void *src) {

  if(!src) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_gml_import", __LINE__, LOGERROR);
    return NULL;
  }

  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_gml_import", __LINE__,
  		   "Unsupported GML type.", LOGERROR);
    return NULL;
  }

  /* If the received source is empty, means that we have to
     return an empty (new) GML */

  switch(format) {
  case GML_FILE:
    return _gml_import_file((char *) src);
  default:
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_gml_import", __LINE__,
  		   "Unsupported GML format.", LOGERROR);
    return NULL;
  }

  return NULL;
 
}

int cpy06_gml_export(gml_t *gml, void *dst, gml_format_t format) {

  if(!gml || gml->scheme != GROUPSIG_CPY06_CODE || !dst) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_gml_export", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_gml_export", __LINE__,
  		   "Unsupported GML format.", LOGERROR);
    return IERROR;
  }

  switch(format) {
  case GML_FILE:
    return _gml_export_file(gml, (char *) dst);
  default:
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_gml_export", __LINE__,
  		   "Unsupported GML format.", LOGERROR);
    return IERROR;
  }

  return IERROR;

}

int cpy06_gml_export_new_entry(void *entry, void *dst, gml_format_t format) {

  if(!entry || !dst) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_gml_export_new_entry", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_gml_export_new_entry", __LINE__,
  		   "Unsupported GML format.", LOGERROR);
    return IERROR;
  }

  switch(format) {
  case GML_FILE:
    return _gml_export_new_entry_file(entry, (char *) dst);
  default:
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_gml_export_new_entry", __LINE__,
  		   "Unsupported GML format.", LOGERROR);
    return IERROR;
  }

  return IERROR;  

}

/* cpy06_gml.c ends here */
