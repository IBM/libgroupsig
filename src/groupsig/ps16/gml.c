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
#include "ps16.h"
#include "groupsig/ps16/gml.h"
#include "groupsig/ps16/identity.h"

/* Private functions */
static int _is_supported_format(gml_format_t format) {
  
  uint32_t i;
  
  for(i=0; i<PS16_SUPPORTED_GML_FORMATS_N; i++) {
    if(format == PS16_SUPPORTED_GML_FORMATS[i]) return 1;
  }
  
  return 0;
  
}

static ps16_gml_entry_t* _gml_entry_import_file(FILE *fd, gml_format_t format,
						 uint8_t *eof) {

  /* identity_t *id; */
  /* trapdoor_t *trap; */
  ps16_gml_entry_t *entry;
  char *line, *sid, *stau, *sttau;
  int rc;
    
  if(!fd || !eof) {
    LOG_EINVAL(&logger, __FILE__, "_gml_entry_import_file",
 	       __LINE__, LOGERROR);
    return NULL;
  }

  entry = NULL; line = NULL; stau = NULL; sttau = NULL;
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

  if(!(stau = (char *) malloc(sizeof(char)*strlen(line)+1))) {
    LOG_ERRORCODE(&logger, __FILE__, "_gml_entry_import_file", __LINE__,
		  errno, LOGERROR);
    GOTOENDRC(IERROR, _gml_entry_import_file);
  }
  memset(stau, 0, strlen(line)+1);

  if(!(sttau = (char *) malloc(sizeof(char)*strlen(line)+1))) {
    LOG_ERRORCODE(&logger, __FILE__, "_gml_entry_import_file", __LINE__,
		  errno, LOGERROR);
    GOTOENDRC(IERROR, _gml_entry_import_file);
  }
  memset(sttau, 0, strlen(line)+1);  

  /* The lines have the format "<id>\t<tau>\t<ttau>" */
  if((rc = sscanf(line, "%s\t%s\t%s", sid, stau, sttau)) == EOF) {
    LOG_ERRORCODE(&logger, __FILE__, "_gml_entry_import_file", __LINE__,
		  errno, LOGERROR);
    GOTOENDRC(IERROR, _gml_entry_import_file);
  }

  if(rc != 3) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_gml_entry_import_file", __LINE__,
		      EDQUOT, "Corrupted GML file.", LOGERROR);
    GOTOENDRC(IERROR, _gml_entry_import_file);
  }

  /* Create the entry and fill it */
  if(!(entry = ps16_gml_entry_init()))
    GOTOENDRC(IERROR, _gml_entry_import_file);
  
  if(!(entry->id = identity_from_string(GROUPSIG_PS16_CODE, sid))) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_gml_entry_import_file", __LINE__,
		      EDQUOT, "Corrupted GML file.", LOGERROR);
    GOTOENDRC(IERROR, _gml_entry_import_file);    
  }
  
  if(!(entry->tau = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, _gml_entry_import_file);
  if(pbcext_element_G1_from_b64(entry->tau, stau) == IERROR) {
    identity_free(entry->id); entry->id = NULL;
    GOTOENDRC(IERROR, _gml_entry_import_file);
  }

  if(!(entry->ttau = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, _gml_entry_import_file);
  if(pbcext_element_G2_from_b64(entry->ttau, sttau) == IERROR) {
    identity_free(entry->id); entry->id = NULL;
    GOTOENDRC(IERROR, _gml_entry_import_file);
  }  

 _gml_entry_import_file_end:

  if(line) { mem_free(line); line = NULL; }
  if(sid) { mem_free(sid); sid = NULL; }
  if(stau) { mem_free(stau); stau = NULL; }
  if(sttau) { mem_free(sttau); sttau = NULL; }

  if(rc == IERROR) {
    if(entry){
      ps16_gml_entry_free(entry); entry = NULL;
    }
  }
  
  return entry;

}

static gml_t* _gml_import_file(char *filename) {

  gml_t *gml;
  ps16_gml_entry_t *entry;
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

  if(!(gml = ps16_gml_init())) {
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
      gml_free(gml); gml = NULL;
      fclose(fd);
      return NULL;
    }

    /* If we got one, store it in the GML structure */
    if(entry) {
      if(gml_insert(gml,entry) == IERROR) {
        gml_free(gml); gml = NULL;
        fclose(fd);
        return NULL;
      }
    }
  }

  fclose(fd); fd = NULL;
  return gml;

}

static int _gml_export_new_entry_file(ps16_gml_entry_t *entry, char *filename) {

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
  
  if(!(sentry = ps16_gml_entry_to_string(entry))) {
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
    if(!(sentry = ps16_gml_entry_to_string((ps16_gml_entry_t *) gml->entries[i]))) {
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

ps16_gml_entry_t* ps16_gml_entry_init() {

  ps16_gml_entry_t *entry;

  if(!(entry = (ps16_gml_entry_t *) malloc(sizeof(ps16_gml_entry_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "ps16_gml_entry_init", __LINE__,
		  errno, LOGERROR);
    return NULL;
  }

  if(!(entry->id = identity_init(GROUPSIG_PS16_CODE))) {
    identity_free(entry->id); entry->id = NULL;
    mem_free(entry); entry = NULL;
    return NULL;
  }
  
  return entry;

}


int ps16_gml_entry_free(ps16_gml_entry_t *entry) {

  if(!entry) {
    LOG_EINVAL_MSG(&logger, __FILE__, "ps16_gml_entry_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if(entry->id) { identity_free(entry->id); entry->id = NULL; }
  if(entry->tau) { pbcext_element_G1_clear(entry->tau); entry->tau = NULL; }
  if(entry->ttau) { pbcext_element_G2_clear(entry->ttau); entry->ttau = NULL; }
  mem_free(entry); entry = NULL;
  
  return IOK;

}

char* ps16_gml_entry_to_string(ps16_gml_entry_t *entry) {

  char *stau, *sttau, *sid, *sentry;
  uint64_t sentry_len;

  if(!entry) {
    LOG_EINVAL(&logger, __FILE__, "ps16_gml_entry_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  /* A string representation of a GML entry will be: 
     <id>\t<tau>\t<ttau> */

  /* Get the string representations of the entry's fields */
  if(!(sid = identity_to_string(entry->id))) {
    return NULL;
  }

  if(!(stau = pbcext_element_G1_to_b64(entry->tau))) {
    mem_free(sid); sid = NULL;
    return NULL;
  }

  if(!(sttau = pbcext_element_G2_to_b64(entry->ttau))) {
    mem_free(sid); sid = NULL;
    mem_free(stau); stau = NULL;
    return NULL;
  }  

  /* Calculate the length of the entry, adding a tab and a \n */
  sentry_len = strlen(sid)+strlen(stau)+strlen(sttau)+2;

  if(!(sentry = (char *) malloc(sizeof(char)*(sentry_len+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "ps16_gml_entry_to_string", __LINE__, errno,
		  LOGERROR);
    mem_free(sid); sid = NULL;    
    mem_free(stau); stau = NULL;
    mem_free(sttau); sttau = NULL;
    return NULL;
  }

  memset(sentry, 0, sizeof(char)*(sentry_len+1));
  sprintf(sentry, "%s\t%s\t%s", sid, stau, sttau);

  mem_free(sid); sid = NULL;
  mem_free(stau); stau = NULL;
  mem_free(sttau); sttau = NULL;

  return sentry;
 
}

/* list functions */

gml_t* ps16_gml_init() {

  gml_t *gml;

  if(!(gml = (gml_t *) malloc(sizeof(gml_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "ps16_gml_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  gml->scheme = GROUPSIG_PS16_CODE;
  gml->entries = NULL;
  gml->n = 0;

  return gml;

}

int ps16_gml_free(gml_t *gml) {

  uint64_t i;

  if(!gml || gml->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "ps16_gml_free", __LINE__,
  		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  for(i=0; i<gml->n; i++) {
    ps16_gml_entry_free(gml->entries[i]); gml->entries[i] = NULL;
  }

  mem_free(gml->entries); gml->entries = NULL;
  mem_free(gml); gml = NULL;

  return IOK;

}

int ps16_gml_insert(gml_t *gml, void *entry) {

  if(!gml || gml->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_gml_insert", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(gml->entries = (void **) 
       realloc(gml->entries, sizeof(ps16_gml_entry_t *)*(gml->n+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "ps16_gml_insert", __LINE__, errno, LOGERROR);
    return IERROR;
  }

  gml->entries[gml->n] = entry;
  gml->n++;

  return IOK;

}

int ps16_gml_remove(gml_t *gml, uint64_t index) {

  if(!gml || gml->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_gml_remove", __LINE__, LOGERROR);
    return IERROR;
  }

  if(index >= gml->n) {
    LOG_EINVAL_MSG(&logger, __FILE__, "ps16_gml_remove", __LINE__, "Invalid index.",
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

void* ps16_gml_get(gml_t *gml, uint64_t index) {

  if(!gml || gml->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_gml_get", __LINE__, LOGERROR);
    return NULL;
  }

  if(index >= gml->n) {
    LOG_EINVAL_MSG(&logger, __FILE__, "ps16_gml_get", __LINE__, "Invalid index.",
  		   LOGERROR);
    return NULL;
  }

  return gml->entries[index];
  
}

gml_t* ps16_gml_import(gml_format_t format, void *src) {

  if(!src) {
    LOG_EINVAL(&logger, __FILE__, "ps16_gml_import", __LINE__, LOGERROR);
    return NULL;
  }

  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "ps16_gml_import", __LINE__,
  		   "Unsupported GML type.", LOGERROR);
    return NULL;
  }

  /* If the received source is empty, means that we have to
     return an empty (new) GML */

  switch(format) {
  case GML_FILE:
    return _gml_import_file((char *) src);
  default:
    LOG_EINVAL_MSG(&logger, __FILE__, "ps16_gml_import", __LINE__,
  		   "Unsupported GML format.", LOGERROR);
    return NULL;
  }

  return NULL;
 
}

int ps16_gml_export(gml_t *gml, void *dst, gml_format_t format) {

  if(!gml || gml->scheme != GROUPSIG_PS16_CODE || !dst) {
    LOG_EINVAL(&logger, __FILE__, "ps16_gml_export", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "ps16_gml_export", __LINE__,
  		   "Unsupported GML format.", LOGERROR);
    return IERROR;
  }

  switch(format) {
  case GML_FILE:
    return _gml_export_file(gml, (char *) dst);
  default:
    LOG_EINVAL_MSG(&logger, __FILE__, "ps16_gml_export", __LINE__,
  		   "Unsupported GML format.", LOGERROR);
    return IERROR;
  }

  return IERROR;

}

int ps16_gml_export_new_entry(void *entry, void *dst, gml_format_t format) {

  if(!entry || !dst) {
    LOG_EINVAL(&logger, __FILE__, "ps16_gml_export_new_entry", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "ps16_gml_export_new_entry", __LINE__,
  		   "Unsupported GML format.", LOGERROR);
    return IERROR;
  }

  switch(format) {
  case GML_FILE:
    return _gml_export_new_entry_file(entry, (char *) dst);
  default:
    LOG_EINVAL_MSG(&logger, __FILE__, "ps16_gml_export_new_entry", __LINE__,
  		   "Unsupported GML format.", LOGERROR);
    return IERROR;
  }

  return IERROR;  

}

/* ps16_gml.c ends here */
