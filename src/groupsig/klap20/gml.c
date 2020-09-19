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
#include "klap20.h"
#include "groupsig/klap20/gml.h"
#include "shim/pbc_ext.h"

gml_t* klap20_gml_init() {

  gml_t *gml;

  if(!(gml = (gml_t *) malloc(sizeof(gml_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "klap20_gml_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  gml->scheme = GROUPSIG_KLAP20_CODE;
  gml->entries = NULL;
  gml->n = 0;

  return gml;

}

int klap20_gml_free(gml_t *gml) {

  uint64_t i;

  if(!gml || gml->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "klap20_gml_free", __LINE__,
  		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if (gml->entries) {
    for(i=0; i<gml->n; i++) {
      klap20_gml_entry_free(gml->entries[i]); gml->entries[i] = NULL;
    }
    mem_free(gml->entries); gml->entries = NULL;    
  }

  mem_free(gml); gml = NULL;

  return IOK;

}

int klap20_gml_insert(gml_t *gml, gml_entry_t *entry) {

  if(!gml || gml->scheme != GROUPSIG_KLAP20_CODE ||
     gml->scheme != entry->scheme) {
    LOG_EINVAL(&logger, __FILE__, "klap20_gml_insert", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(gml->entries = (gml_entry_t **) 
       realloc(gml->entries, sizeof(gml_entry_t *)*(gml->n+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "klap20_gml_insert", __LINE__, errno,
		  LOGERROR);
    return IERROR;
  }

  gml->entries[gml->n] = entry;
  gml->n++;

  return IOK;

}

int klap20_gml_remove(gml_t *gml, uint64_t index) {

  if(!gml || gml->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_gml_remove", __LINE__, LOGERROR);
    return IERROR;
  }

  if(index >= gml->n) {
    LOG_EINVAL_MSG(&logger, __FILE__, "klap20_gml_remove", __LINE__,
		   "Invalid index.", LOGERROR);
    return IERROR;
  }

  /* Just set it to NULL */
  /** @todo This will generate a lot of unused memory! Use some other ADT */
  gml->entries[index] = NULL;
  
  /* Decrement the number of entries */
  gml->n--;

  return IOK;

}

gml_entry_t* klap20_gml_get(gml_t *gml, uint64_t index) {

  if(!gml || gml->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_gml_get", __LINE__, LOGERROR);
    return NULL;
  }

  if(index >= gml->n) {
    LOG_EINVAL_MSG(&logger, __FILE__, "klap20_gml_get", __LINE__, "Invalid index.",
  		   LOGERROR);
    return NULL;
  }

  return gml->entries[index];
  
}

int klap20_gml_export(byte_t **bytes, uint32_t *size, gml_t *gml) {

  byte_t *bentry, *_bytes;
  uint64_t i;
  int rc;  
  uint32_t total_size, entry_size;
  
  if (!bytes || !size || !gml || gml->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_gml_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  total_size = entry_size = 0;
  bentry = _bytes = NULL;

  /* Dump the number of entries */
  if (!(_bytes = mem_malloc(sizeof(uint64_t))))
    GOTOENDRC(IERROR, klap20_gml_export);
  memcpy(_bytes, &gml->n, sizeof(uint64_t));
  total_size = sizeof(uint64_t);

  /* Export the entries one by one */
  for (i=0; i<gml->n; i++) {
    if (gml_entry_export(&bentry, &entry_size, gml->entries[i]) == IERROR)
      GOTOENDRC(IERROR, klap20_gml_export);
    total_size += entry_size;
    if (!(_bytes = mem_realloc(_bytes, total_size)))
      GOTOENDRC(IERROR, klap20_gml_export);
    memcpy(&_bytes[total_size-entry_size], bentry, entry_size);
    mem_free(bentry); bentry = NULL;
  }

  if (!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, total_size);
    mem_free(_bytes); _bytes = NULL;
  }

  *size = total_size;

 klap20_gml_export_end:

  if (rc == IERROR) {
    if (_bytes) { mem_free(_bytes); _bytes = NULL; }
  }

  if (bentry) { mem_free(bentry); bentry = NULL; }
  
  return rc;

}

gml_t* klap20_gml_import(byte_t *bytes, uint32_t size) {

  gml_t *gml;
  uint64_t i;
  uint32_t read;
  int entry_size;
  int rc;
  FILE *fd;
  
  if(!bytes || !size) {
    LOG_EINVAL(&logger, __FILE__, "klap20_gml_import", __LINE__, LOGERROR);
    return NULL;
  }

  read = 0;
  gml = NULL;
  rc = IOK;

  if (!(gml = klap20_gml_init())) GOTOENDRC(IERROR, klap20_gml_import);

  /* Read the nubmer of entries to process */
  memcpy(&gml->n, bytes, sizeof(uint64_t));
  read += sizeof(uint64_t);

  if (!(gml->entries = mem_malloc(sizeof(gml_entry_t *)*gml->n)))
    GOTOENDRC(IERROR, klap20_gml_import);

  /* Import the entries one by one */
  for (i=0; i<gml->n; i++) {

    if (!(gml->entries[i] = klap20_gml_entry_import(&bytes[read], size-read)))
      GOTOENDRC(IERROR, klap20_gml_import);

    if ((entry_size = klap20_gml_entry_get_size(gml->entries[i])) == -1)
      GOTOENDRC(IERROR, klap20_gml_import);

    read += entry_size;
    
  }

 klap20_gml_import_end:
  
  if (rc == IERROR) {
    klap20_gml_free(gml);
    gml = NULL;
  }
  
  return gml;
 
}

gml_entry_t* klap20_gml_entry_init() {

  gml_entry_t *entry;

  if(!(entry = (gml_entry_t *) malloc(sizeof(gml_entry_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "klap20_gml_entry_init", __LINE__,
		  errno, LOGERROR);
    return NULL;
  }

  entry->scheme = GROUPSIG_KLAP20_CODE;
  entry->id = UINT64_MAX;
  entry->data = NULL;
  
  return entry;

}


int klap20_gml_entry_free(gml_entry_t *entry) {

  klap20_gml_entry_data_t *data;
  int rc;
  
  if(!entry) {
    LOG_EINVAL_MSG(&logger, __FILE__, "klap20_gml_entry_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  rc = IOK;
  data = (klap20_gml_entry_data_t *) entry->data;

  if (data) {
    if (data->SS0) { rc = pbcext_element_G2_free(data->SS0); data->SS0 = NULL; }
    if (data->SS1) { rc = pbcext_element_G2_free(data->SS1); data->SS1 = NULL; }
    if (data->ff0) { rc = pbcext_element_G2_free(data->ff0); data->ff0 = NULL; }
    if (data->ff1) { rc = pbcext_element_G2_free(data->ff1); data->ff1 = NULL; }
    if (data->tau) { rc = pbcext_element_GT_free(data->tau); data->tau = NULL; }
    mem_free(entry->data); entry->data = NULL;
  }
  
  mem_free(entry); entry = NULL;

  if (rc) rc = IERROR;
  return rc;

}

int klap20_gml_entry_get_size(gml_entry_t *entry) {

  uint64_t sSS0, sSS1, sff0, sff1;
  
  if (!entry) {
    LOG_EINVAL(&logger, __FILE__, "klap20_gml_entry_get_size", __LINE__, LOGERROR);
    return -1;
  }

  if (pbcext_element_G2_byte_size(&sSS0) == -1)
    return -1;
  
  if (pbcext_element_G2_byte_size(&sSS1) == -1)
    return -1;

  if (pbcext_element_G2_byte_size(&sff0) == -1)
    return -1;

  if (pbcext_element_G2_byte_size(&sff1) == -1)
    return -1;  

  if (sSS0 + sSS1 + sff0 + sff1 > INT_MAX) return -1;

  return (int) sSS0 + sSS1 + sff0 + sff1 + sizeof(int)*4;
  
}

int klap20_gml_entry_export(byte_t **bytes,
			    uint32_t *size,
			    gml_entry_t *entry) {

  klap20_gml_entry_data_t *klap20_data;
  byte_t *_bytes, *__bytes;
  uint64_t _size, len, offset;
  
  if (!bytes || !size || !entry) {
    LOG_EINVAL(&logger, __FILE__, "klap20_gml_entry_export", __LINE__, LOGERROR);
    return IERROR;    
  }

  klap20_data = (klap20_gml_entry_data_t *) entry->data;  
  
  /* Calculate size */
  if ((_size = klap20_gml_entry_get_size(entry)) == -1) return IERROR;
  _size += sizeof(int) + sizeof(uint64_t);
  
  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) return IERROR;

  /* First, dump the identity */
  memcpy(_bytes, &entry->id, sizeof(uint64_t));
  offset = sizeof(uint64_t);

  /* Next, dump the data */
  __bytes = &_bytes[offset];
  if (pbcext_dump_element_G2_bytes(&__bytes, &len, klap20_data->SS0) == IERROR) {
    mem_free(_bytes); _bytes = NULL;
    return IERROR;
  }
  offset += len;

  __bytes = &_bytes[offset];  
  if (pbcext_dump_element_G2_bytes(&__bytes, &len, klap20_data->SS1) == IERROR) {
    mem_free(_bytes); _bytes = NULL;
    return IERROR;
  }
  offset += len;

  __bytes = &_bytes[offset];  
  if (pbcext_dump_element_G2_bytes(&__bytes, &len, klap20_data->ff0) == IERROR) {
    mem_free(_bytes); _bytes = NULL;
    return IERROR;
  }
  offset += len;

  __bytes = &_bytes[offset];  
  if (pbcext_dump_element_G2_bytes(&__bytes, &len, klap20_data->ff1) == IERROR) {
    mem_free(_bytes); _bytes = NULL;
    return IERROR;
  }

  /* Prepare exit */
  if (!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, _size);
    mem_free(_bytes); _bytes = NULL;
  }

  *size = _size;

  return IOK;
  
}

gml_entry_t* klap20_gml_entry_import(byte_t *bytes, uint32_t size) {

  gml_entry_t *entry;
  klap20_gml_entry_data_t *klap20_data;
  uint64_t len, offset;
  FILE *fd;

  if (!bytes || !size) {
    LOG_EINVAL(&logger, __FILE__, "klap20_gml_entry_import", __LINE__, LOGERROR);
    return NULL;    
  }

  if (!(entry = klap20_gml_entry_init())) return NULL;

  /* First, read the identity */
  memcpy(&entry->id, bytes, sizeof(uint64_t));
  offset = sizeof(uint64_t);

  /* Next, read the data */

  if (!(entry->data = mem_malloc(sizeof(klap20_gml_entry_data_t)))) {
    klap20_gml_entry_free(entry); entry = NULL;
    return NULL;
  }

  klap20_data = (klap20_gml_entry_data_t *) entry->data;
  
  if(!(klap20_data->SS0 = pbcext_element_G2_init())) {
    klap20_gml_entry_free(entry); entry = NULL;
    return NULL;
  }

  if (pbcext_get_element_G2_bytes(klap20_data->SS0,
				  &len,
				  &bytes[offset]) == IERROR) {
    klap20_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  if (!len) {
    klap20_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  offset += len;

  if(!(klap20_data->SS1 = pbcext_element_G2_init())) {
    klap20_gml_entry_free(entry); entry = NULL;
    return NULL;
  }

  if (pbcext_get_element_G2_bytes(klap20_data->SS1,
				  &len,
				  &bytes[offset]) == IERROR) {
    klap20_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  if (!len) {
    klap20_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  offset += len;

  if(!(klap20_data->ff0 = pbcext_element_G2_init())) {
    klap20_gml_entry_free(entry); entry = NULL;
    return NULL;
  }

  if (pbcext_get_element_G2_bytes(klap20_data->ff0,
				  &len,
				  &bytes[offset]) == IERROR) {
    klap20_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  if (!len) {
    klap20_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  offset += len;

  if(!(klap20_data->ff1 = pbcext_element_G2_init())) {
    klap20_gml_entry_free(entry); entry = NULL;
    return NULL;
  }

  if (pbcext_get_element_G2_bytes(klap20_data->ff1,
				  &len,
				  &bytes[offset]) == IERROR) {
    klap20_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  if (!len) {
    klap20_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  offset += len;  

  return entry;
  
}

char* klap20_gml_entry_to_string(gml_entry_t *entry) {

  klap20_gml_entry_data_t *klap20_data;
  char *sSS0, *sSS1, *sff0, *sff1, *sid, *sentry;
  uint64_t sSS0_len, sSS1_len, sff0_len, sff1_len, sentry_len;
  int rc;

  if(!entry) {
    LOG_EINVAL(&logger, __FILE__, "klap20_gml_entry_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  sSS0 = sSS1 = sff0 = sff1 = sid = sentry = NULL;

  klap20_data = (klap20_gml_entry_data_t *) entry->data;

  /* A string representation of a GML entry will be: 
     <id>\t<SS0>\t<SS1>\t<ff0>\t<ff1> */

  /* Get the string representations of the entry's fields */
  if(!(sid = misc_uint642string(entry->id))) {
    return NULL;
  }

  sSS0 = NULL;
  if(pbcext_element_G2_to_string(&sSS0, &sSS0_len, 16, klap20_data->SS0) == IERROR)
    GOTOENDRC(IERROR, klap20_gml_entry_to_string);

  sSS1 = NULL;
  if(pbcext_element_G2_to_string(&sSS1, &sSS1_len, 16, klap20_data->SS1) == IERROR)
    GOTOENDRC(IERROR, klap20_gml_entry_to_string);    

  sff0 = NULL;
  if(pbcext_element_G2_to_string(&sff0, &sff0_len, 16, klap20_data->ff0) == IERROR)
    GOTOENDRC(IERROR, klap20_gml_entry_to_string);   

  sff1 = NULL;
  if(pbcext_element_G2_to_string(&sff1, &sff1_len, 16, klap20_data->ff1) == IERROR)
    GOTOENDRC(IERROR, klap20_gml_entry_to_string);

  sentry_len = strlen(sid)+sSS0_len+sSS1_len+sff0_len+sff1_len+5;

  if(!(sentry = (char *) mem_malloc(sizeof(char)*sentry_len))) {
    LOG_ERRORCODE(&logger, __FILE__, "klap20_gml_entry_to_string",
		  __LINE__, errno, LOGERROR);
    GOTOENDRC(IERROR, klap20_gml_entry_to_string);    
  }

  sprintf(sentry, "%s\t%s\t%s\t%s\t%s", sid, sSS0, sSS1, sff0, sff1);

 klap20_gml_entry_to_string_end:
  
  if (sid) { mem_free(sid); sid = NULL; }
  if (sSS0) { mem_free(sSS0); sSS0 = NULL; }
  if (sSS1) { mem_free(sSS1); sSS1 = NULL; }
  if (sff0) { mem_free(sff0); sff0 = NULL; }
  if (sff1) { mem_free(sff1); sff1 = NULL;  }

  return sentry;
 
}

/* gml.c ends here */
