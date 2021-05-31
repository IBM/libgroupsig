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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "dl21.h"
#include "groupsig/dl21/mgr_key.h"
#include "misc/misc.h"
#include "shim/base64.h"
#include "sys/mem.h"

groupsig_key_t* dl21_mgr_key_init() {

    groupsig_key_t *key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (dl21_mgr_key_t *) mem_malloc(sizeof(dl21_mgr_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_DL21_CODE;

  return key;

}

int dl21_mgr_key_free(groupsig_key_t *key) {

  dl21_mgr_key_t *dl21_key;
  
 if(key->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_mgr_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    dl21_key = key->key;
    pbcext_element_Fr_free(dl21_key->isk); dl21_key->isk = NULL;
    mem_free(key->key);
    key->key = NULL;
  }
  
  mem_free(key);
  
  return IOK;

}

int dl21_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  dl21_mgr_key_t *dl21_dst, *dl21_src;

  if (!dst || dst->scheme != GROUPSIG_DL21_CODE ||
     !src || src->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_mgr_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  dl21_dst = dst->key;
  dl21_src = src->key;

  /* Copy the elements */
  if (dl21_src->isk) {
    if (!(dl21_dst->isk = pbcext_element_Fr_init())) return IERROR;
    if (pbcext_element_Fr_set(dl21_dst->isk, dl21_src->isk) == IERROR) {
      pbcext_element_Fr_free(dl21_dst->isk); dl21_dst->isk = NULL;
      return IERROR;
    }
  }

  return IOK;

}

int dl21_mgr_key_get_size(groupsig_key_t *key) {

  dl21_mgr_key_t *dl21_key;
  uint64_t sisk;
  int size;

  if(!key || key->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_mgr_key_get_size",
	       __LINE__, LOGERROR);
    return -1;
  }

  dl21_key = key->key;
  sisk = 0;

  if (dl21_key->isk) { if(pbcext_element_Fr_byte_size(&sisk) == IERROR) return -1; }

  if ((int) sisk + sizeof(int)*1+2 > INT_MAX) return -1;
  size = (int) sisk + sizeof(int)*1+2;

  return size;

}

int dl21_mgr_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key) {

  dl21_mgr_key_t *dl21_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  uint32_t _size;
  int ctr, rc;
  
  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_mgr_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  dl21_key = key->key;

  if ((_size = dl21_mgr_key_get_size(key)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }

  /* Dump GROUPSIG_DL21_CODE */
  _bytes[ctr++] = GROUPSIG_DL21_CODE;

  /* Dump key type */
  _bytes[ctr++] = GROUPSIG_KEY_MGRKEY;

  /* Dump isk */
  if(dl21_key->isk) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, dl21_key->isk) == IERROR)
      GOTOENDRC(IERROR, dl21_mgr_key_export);
    ctr += len;
  } else {
    ctr += sizeof(int);
  }

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "dl21_mgr_key_export", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, dl21_mgr_key_export);
  }

  *size = ctr;

 dl21_mgr_key_export_end:

  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  
  return rc;
  
}

groupsig_key_t* dl21_mgr_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  dl21_mgr_key_t *dl21_key;
  uint64_t len;
  int rc, ctr;
  uint8_t type, scheme;  
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "dl21_mgr_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(key = dl21_mgr_key_init())) {
    return NULL;
  }
  dl21_key = key->key;    

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "dl21_mgr_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, dl21_mgr_key_import);
  }  

  /* Next byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MGRKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "dl21_mgr_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, dl21_mgr_key_import);
  }    

  /* Get isk */
  if(!(dl21_key->isk = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, dl21_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(dl21_key->isk, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21_mgr_key_import);

  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(dl21_key->isk); dl21_key->isk = NULL;
  } else {
    ctr += len;
  }

 dl21_mgr_key_import_end:
  
  if(rc == IERROR && key) { dl21_mgr_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  return NULL;  

}

char* dl21_mgr_key_to_string(groupsig_key_t *key) {

  if(!key || key->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_mgr_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  return NULL;

}

/* mgr_key.c ends here */
