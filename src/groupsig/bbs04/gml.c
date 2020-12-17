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
#include "shim/pbc_ext.h"
#include "sys/mem.h"
#include "bbs04.h"
#include "groupsig/bbs04/gml.h"

gml_t* bbs04_gml_init() {

  gml_t *gml;

  if(!(gml = (gml_t *) malloc(sizeof(gml_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "bbs04_gml_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  gml->scheme = GROUPSIG_BBS04_CODE;
  gml->entries = NULL;
  gml->n = 0;

  return gml;

}

int bbs04_gml_free(gml_t *gml) {

  uint64_t i;

  if(!gml || gml->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "bbs04_gml_free", __LINE__,
  		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  for(i=0; i<gml->n; i++) {
    bbs04_gml_entry_free(gml->entries[i]); gml->entries[i] = NULL;
  }

  mem_free(gml->entries); gml->entries = NULL;
  mem_free(gml); gml = NULL;

  return IOK;

}

int bbs04_gml_insert(gml_t *gml, gml_entry_t *entry) {

  if(!gml || gml->scheme != GROUPSIG_BBS04_CODE ||
     gml->scheme != entry->scheme) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_gml_insert", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(gml->entries = (gml_entry_t **) 
       realloc(gml->entries, sizeof(gml_entry_t *)*(gml->n+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "bbs04_gml_insert", __LINE__, errno,
		  LOGERROR);
    return IERROR;
  }

  gml->entries[gml->n] = entry;
  gml->n++;

  return IOK;

}

int bbs04_gml_remove(gml_t *gml, uint64_t index) {

  if(!gml || gml->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_gml_remove", __LINE__, LOGERROR);
    return IERROR;
  }

  if(index >= gml->n) {
    LOG_EINVAL_MSG(&logger, __FILE__, "bbs04_gml_remove", __LINE__,
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

gml_entry_t* bbs04_gml_get(gml_t *gml, uint64_t index) {

  if(!gml || gml->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_gml_get", __LINE__, LOGERROR);
    return NULL;
  }

  if(index >= gml->n) {
    LOG_EINVAL_MSG(&logger, __FILE__, "bbs04_gml_get", __LINE__, "Invalid index.",
  		   LOGERROR);
    return NULL;
  }

  return gml->entries[index];
  
}

int bbs04_gml_export(byte_t **bytes, uint32_t *size, gml_t *gml) {

  byte_t *bentry, *_bytes;
  uint64_t i;
  int rc;  
  uint32_t total_size, entry_size;
  
  if (!bytes || !size || !gml || gml->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_gml_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  total_size = entry_size = 0;
  bentry = _bytes = NULL;

  /* Dump the number of entries */
  if (!(_bytes = mem_malloc(sizeof(uint64_t))))
    GOTOENDRC(IERROR, bbs04_gml_export);
  memcpy(_bytes, &gml->n, sizeof(uint64_t));
  total_size = sizeof(uint64_t);

  /* Export the entries one by one */
  for (i=0; i<gml->n; i++) {
    if (gml_entry_export(&bentry, &entry_size, gml->entries[i]) == IERROR)
      GOTOENDRC(IERROR, bbs04_gml_export);
    total_size += entry_size;
    if (!(_bytes = mem_realloc(_bytes, total_size)))
      GOTOENDRC(IERROR, bbs04_gml_export);
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

 bbs04_gml_export_end:

  if (rc == IERROR) {
    if (_bytes) { mem_free(_bytes); _bytes = NULL; }
  }

  if (bentry) { mem_free(bentry); bentry = NULL; }
  
  return rc;

}

gml_t* bbs04_gml_import(byte_t *bytes, uint32_t size) {

  gml_t *gml;
  uint64_t i;
  uint32_t read;
  int entry_size, rc;
  
  if(!bytes || !size) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_gml_import", __LINE__, LOGERROR);
    return NULL;
  }

  read = 0;
  gml = NULL;
  rc = IOK;
  
  if (!(gml = bbs04_gml_init())) GOTOENDRC(IERROR, bbs04_gml_import);

  /* Read the nubmer of entries to process */
  memcpy(&gml->n, bytes, sizeof(uint64_t));
  read += sizeof(uint64_t);

  if (!(gml->entries = mem_malloc(sizeof(gml_entry_t *)*gml->n)))
    GOTOENDRC(IERROR, bbs04_gml_import);

  /* Import the entries one by one */
  for (i=0; i<gml->n; i++) {

    if (!(gml->entries[i] = bbs04_gml_entry_import(&bytes[read], size-read)))
      GOTOENDRC(IERROR, bbs04_gml_import);
    
    if ((entry_size = bbs04_gml_entry_get_size(gml->entries[i])) == -1)
      GOTOENDRC(IERROR, bbs04_gml_import);

    read += entry_size;
    
  }

 bbs04_gml_import_end:
  
  if (rc == IERROR) {
    bbs04_gml_free(gml);
    gml = NULL;
  }
  
  return gml;
 
}

gml_entry_t* bbs04_gml_entry_init() {

  gml_entry_t *entry;

  if(!(entry = (gml_entry_t *) malloc(sizeof(gml_entry_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "bbs04_gml_entry_init", __LINE__,
		  errno, LOGERROR);
    return NULL;
  }

  entry->scheme = GROUPSIG_BBS04_CODE;
  entry->id = 0;
  entry->data = NULL;
  
  return entry;

}


int bbs04_gml_entry_free(gml_entry_t *entry) {

  int rc;
  
  if(!entry) {
    LOG_EINVAL_MSG(&logger, __FILE__, "bbs04_gml_entry_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  rc = IOK;

  if(entry->data) {
    rc = pbcext_element_G1_free(entry->data);
    entry->data = NULL;
  }
  
  mem_free(entry); 
  
  return rc;

}

int bbs04_gml_entry_get_size(gml_entry_t *entry) {

  uint64_t sG1;
  
  if (!entry) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_gml_entry_get_size", __LINE__, LOGERROR);
    return -1;
  }

  if (pbcext_element_G1_byte_size(&sG1) == -1)
    return -1;

  if (sG1 > INT_MAX) return -1;

  return (int) sG1 + sizeof(int);
  
  
}

int bbs04_gml_entry_export(byte_t **bytes,
			   uint32_t *size,
			   gml_entry_t *entry) {

  byte_t *_bytes, *__bytes;
  uint64_t _size, len;
  
  if (!bytes || !size || !entry) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_gml_entry_export", __LINE__, LOGERROR);
    return IERROR;    
  }

  /* Calculate size */
  if ((_size = bbs04_gml_entry_get_size(entry)) == -1) return IERROR;
  _size += sizeof(int) + sizeof(uint64_t);
  
  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) return IERROR;

  /* First, dump the identity */
  memcpy(_bytes, &entry->id, sizeof(uint64_t));

  /* Next, dump the data, which for BBS04 is just the G1 element */
  __bytes = &_bytes[sizeof(uint64_t)];
  if (pbcext_dump_element_G1_bytes(&__bytes,
				   &len,
				   entry->data) == IERROR) {
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

gml_entry_t* bbs04_gml_entry_import(byte_t *bytes, uint32_t size) {

  gml_entry_t *entry;
  uint64_t len;

  if (!bytes || !size) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_gml_entry_import", __LINE__, LOGERROR);
    return NULL;    
  }

  if (!(entry = bbs04_gml_entry_init())) return NULL;

  /* First, read the identity */
  memcpy(&entry->id, bytes, sizeof(uint64_t));

  /* Next, read the data (just a G1 element) */
  if(!(entry->data = pbcext_element_G1_init())) {
    bbs04_gml_entry_free(entry); entry = NULL;
    return NULL;
  }
  
  if (pbcext_get_element_G1_bytes(entry->data,
				  &len,
				  &bytes[sizeof(uint64_t)]) == IERROR) {
    bbs04_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  if (!len) {
    bbs04_gml_entry_free(entry); entry = NULL;
    return NULL;    
  }

  return entry;
  
}

char* bbs04_gml_entry_to_string(gml_entry_t *entry) {

  char *sdata, *sid, *sentry;
  uint64_t sdata_len, sentry_len;

  if(!entry) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_gml_entry_to_string",
	       __LINE__, LOGERROR);
    return NULL;
  }

  /* A string representation of a GML entry will be: 
     <id>\t<trapdoor> */

  /* Get the string representations of the entry's fields */
  if(!(sid = misc_uint642string(entry->id))) {
    return NULL;
  }

  sdata = NULL;
  if(pbcext_element_G1_to_string(&sdata, &sdata_len, 16, entry->data) == IERROR) {
    mem_free(sid); sid = NULL;
    return NULL;
  }

  sentry_len = strlen(sid)+sdata_len+strlen("\t");

  if(!(sentry = (char *) mem_malloc(sizeof(char)*sentry_len+1))) {
    LOG_ERRORCODE(&logger, __FILE__, "bbs04_gml_entry_to_string",
		  __LINE__, errno, LOGERROR);
    free(sdata); sdata = NULL;
    mem_free(sid); sid = NULL;
    return NULL;
  }

  sprintf(sentry, "%s\t%s", sid, sdata);

  mem_free(sid); sid = NULL;
  mem_free(sdata); sdata = NULL;

  return sentry;
 
}

/* gml.c ends here */
