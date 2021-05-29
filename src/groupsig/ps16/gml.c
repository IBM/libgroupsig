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
#include "shim/pbc_ext.h"

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

  if (gml->entries) {
    for(i=0; i<gml->n; i++) {
      ps16_gml_entry_free(gml->entries[i]); gml->entries[i] = NULL;
    }
    mem_free(gml->entries); gml->entries = NULL;    
  }

  mem_free(gml); gml = NULL;

  return IOK;

}

int ps16_gml_insert(gml_t *gml, gml_entry_t *entry) {

  if(!gml || gml->scheme != GROUPSIG_PS16_CODE ||
     gml->scheme != entry->scheme) {
    LOG_EINVAL(&logger, __FILE__, "ps16_gml_insert", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(gml->entries = (gml_entry_t **) 
       realloc(gml->entries, sizeof(gml_entry_t *)*(gml->n+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "ps16_gml_insert", __LINE__, errno,
		  LOGERROR);
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
    LOG_EINVAL_MSG(&logger, __FILE__, "ps16_gml_remove", __LINE__,
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

gml_entry_t* ps16_gml_get(gml_t *gml, uint64_t index) {

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

int ps16_gml_export(byte_t **bytes, uint32_t *size, gml_t *gml) {

  byte_t *bentry, *_bytes;
  uint64_t i;
  int rc;  
  uint32_t total_size, entry_size;
  
  if (!bytes || !size || !gml || gml->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_gml_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  total_size = entry_size = 0;
  bentry = _bytes = NULL;

  /* Dump the number of entries */
  if (!(_bytes = mem_malloc(sizeof(uint64_t))))
    GOTOENDRC(IERROR, ps16_gml_export);
  memcpy(_bytes, &gml->n, sizeof(uint64_t));
  total_size = sizeof(uint64_t);

  /* Export the entries one by one */
  for (i=0; i<gml->n; i++) {
    if (gml_entry_export(&bentry, &entry_size, gml->entries[i]) == IERROR)
      GOTOENDRC(IERROR, ps16_gml_export);
    total_size += entry_size;
    if (!(_bytes = mem_realloc(_bytes, total_size)))
      GOTOENDRC(IERROR, ps16_gml_export);
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

 ps16_gml_export_end:

  if (rc == IERROR) {
    if (_bytes) { mem_free(_bytes); _bytes = NULL; }
  }

  if (bentry) { mem_free(bentry); bentry = NULL; }
  
  return rc;

}

gml_t* ps16_gml_import(byte_t *bytes, uint32_t size) {

  gml_t *gml;
  uint64_t i;
  uint32_t read;
  int entry_size;
  int rc;
  FILE *fd;
  
  if(!bytes || !size) {
    LOG_EINVAL(&logger, __FILE__, "ps16_gml_import", __LINE__, LOGERROR);
    return NULL;
  }

  read = 0;
  gml = NULL;
  rc = IOK;

  if (!(gml = ps16_gml_init())) GOTOENDRC(IERROR, ps16_gml_import);

  /* Read the nubmer of entries to process */
  memcpy(&gml->n, bytes, sizeof(uint64_t));
  read += sizeof(uint64_t);

  if (!(gml->entries = mem_malloc(sizeof(gml_entry_t *)*gml->n)))
    GOTOENDRC(IERROR, ps16_gml_import);

  /* Import the entries one by one */
  for (i=0; i<gml->n; i++) {

    if (!(gml->entries[i] = ps16_gml_entry_import(&bytes[read], size-read)))
      GOTOENDRC(IERROR, ps16_gml_import);

    if ((entry_size = ps16_gml_entry_get_size(gml->entries[i])) == -1)
      GOTOENDRC(IERROR, ps16_gml_import);

    read += entry_size;
    
  }

 ps16_gml_import_end:
  
  if (rc == IERROR) {
    ps16_gml_free(gml);
    gml = NULL;
  }
  
  return gml;
 
}

gml_entry_t* ps16_gml_entry_init() {

  gml_entry_t *entry;

  if(!(entry = (gml_entry_t *) malloc(sizeof(gml_entry_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "ps16_gml_entry_init", __LINE__,
		  errno, LOGERROR);
    return NULL;
  }

  entry->scheme = GROUPSIG_PS16_CODE;
  entry->id = UINT64_MAX;
  entry->data = NULL;
  
  return entry;

}


int ps16_gml_entry_free(gml_entry_t *entry) {

  ps16_gml_entry_data_t *data;
  int rc;
  
  if(!entry) {
    LOG_EINVAL_MSG(&logger, __FILE__, "ps16_gml_entry_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  rc = IOK;
  data = (ps16_gml_entry_data_t *) entry->data;

  if (data) {
    if (data->tau) { rc = pbcext_element_G1_free(data->tau); data->tau = NULL; }
    if (data->ttau) { rc += pbcext_element_G2_free(data->ttau); data->ttau = NULL; }
    mem_free(entry->data); entry->data = NULL;
  }
  
  mem_free(entry); entry = NULL;

  if (rc) rc = IERROR;
  return rc;

}

int ps16_gml_entry_get_size(gml_entry_t *entry) {

  uint64_t sG1, sG2;
  
  if (!entry) {
    LOG_EINVAL(&logger, __FILE__, "ps16_gml_entry_get_size", __LINE__, LOGERROR);
    return -1;
  }

  if (pbcext_element_G1_byte_size(&sG1) == -1)
    return -1;
  
  if (pbcext_element_G2_byte_size(&sG2) == -1)
    return -1;

  if (sG1 + sG2 + sizeof(int)*2 + sizeof(uint64_t) > INT_MAX) return -1;

  return (int) sG1 + sG2 + sizeof(int)*2 + sizeof(uint64_t);
  
}

int ps16_gml_entry_export(byte_t **bytes,
			  uint32_t *size,
			  gml_entry_t *entry) {

  byte_t *_bytes, *__bytes;
  uint64_t _size, len;
  int ctr;
  
  if (!bytes || !size || !entry) {
    LOG_EINVAL(&logger, __FILE__, "ps16_gml_entry_export", __LINE__, LOGERROR);
    return IERROR;    
  }

  ctr = 0;

  /* Calculate size */
  if ((_size = ps16_gml_entry_get_size(entry)) == -1) return IERROR;
  //  _size += sizeof(int) + sizeof(uint64_t);
  
  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) return IERROR;

  /* First, dump the identity */
  memcpy(_bytes, &entry->id, sizeof(uint64_t));
  ctr += sizeof(uint64_t);

  /* Next, dump the data, which for PS16 is tau (G1 element) and 
     ttau (G2 element) */
  __bytes = &_bytes[ctr];
  if (pbcext_dump_element_G1_bytes(&__bytes,
				   &len,
				   ((ps16_gml_entry_data_t *) entry->data)->tau) == IERROR) {
    mem_free(_bytes); _bytes = NULL;
    return IERROR;
  }
  ctr += len;  

  __bytes = &_bytes[ctr];  
  if (pbcext_dump_element_G2_bytes(&__bytes,
				   &len,
				   ((ps16_gml_entry_data_t *) entry->data)->ttau) == IERROR) {
    mem_free(_bytes); _bytes = NULL;
    return IERROR;
  }
  ctr += len;

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ps16_gml_entry_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
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

gml_entry_t* ps16_gml_entry_import(byte_t *bytes, uint32_t size) {

  gml_entry_t *entry;
  uint64_t len;
  FILE *fd;

  if (!bytes || !size) {
    LOG_EINVAL(&logger, __FILE__, "ps16_gml_entry_import", __LINE__, LOGERROR);
    return NULL;    
  }

  if (!(entry = ps16_gml_entry_init())) return NULL;

  /* First, read the identity */
  memcpy(&entry->id, bytes, sizeof(uint64_t));

  /* Next, read the data */

  if (!(entry->data = mem_malloc(sizeof(ps16_gml_entry_data_t)))) {
    ps16_gml_entry_free(entry); entry = NULL;
    return NULL;
  }
  
  if(!(((ps16_gml_entry_data_t *)entry->data)->tau = pbcext_element_G1_init())) {
    ps16_gml_entry_free(entry); entry = NULL;
    return NULL;
  }

  if (pbcext_get_element_G1_bytes(((ps16_gml_entry_data_t *)entry->data)->tau,
				  &len,
				  &bytes[sizeof(uint64_t)]) == IERROR) {
    ps16_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  if (!len) {
    ps16_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  if(!(((ps16_gml_entry_data_t *)entry->data)->ttau = pbcext_element_G2_init())) {
    ps16_gml_entry_free(entry); entry = NULL;
    return NULL;
  }

  if (pbcext_get_element_G2_bytes(((ps16_gml_entry_data_t *)entry->data)->ttau,
				  &len,
				  &bytes[sizeof(uint64_t)+len]) == IERROR) {
    ps16_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  if (!len) {
    ps16_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }  

  return entry;
  
}

char* ps16_gml_entry_to_string(gml_entry_t *entry) {

  char *stau, *sttau, *sid, *sentry;
  uint64_t stau_len, sttau_len, sentry_len;

  if(!entry) {
    LOG_EINVAL(&logger, __FILE__, "ps16_gml_entry_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  /* A string representation of a GML entry will be: 
     <id>\t<tau>\t<ttau> */

  /* Get the string representations of the entry's fields */
  if(!(sid = misc_uint642string(entry->id))) {
    return NULL;
  }

  stau = NULL;
  if(pbcext_element_G1_to_string(&stau,
				 &stau_len,
				 16,
				 ((ps16_gml_entry_data_t *)entry->data)->tau) == IERROR) {
    mem_free(sid); sid = NULL;
    return NULL;
  }

  if(pbcext_element_G2_to_string(&sttau,
				 &sttau_len,
				 16,
				 ((ps16_gml_entry_data_t *)entry->data)->ttau) == IERROR) {
    mem_free(sid); sid = NULL;
    mem_free(stau); stau = NULL;    
    return NULL;
  }

  sentry_len = strlen(sid)+stau_len+sttau_len+2;

  if(!(sentry = (char *) mem_malloc(sizeof(char)*sentry_len+1))) {
    LOG_ERRORCODE(&logger, __FILE__, "ps16_gml_entry_to_string", __LINE__, errno,
		  LOGERROR);
    free(stau); stau = NULL;
    free(sttau); sttau = NULL;
    mem_free(sid); sid = NULL;
    return NULL;
  }

  sprintf(sentry, "%s\t%s\t%s", sid, stau, sttau);

  mem_free(sid); sid = NULL;
  mem_free(stau); stau = NULL;
  mem_free(sttau); sttau = NULL;

  return sentry;
 
}

/* gml.c ends here */
