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

#include "klap20.h"
#include "groupsig/klap20/mgr_key.h"
#include "misc/misc.h"
#include "shim/base64.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"

groupsig_key_t* klap20_mgr_key_init() {

  groupsig_key_t *key;
  klap20_mgr_key_t *klap20_key;
  
  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (klap20_mgr_key_t *) mem_malloc(sizeof(klap20_mgr_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_KLAP20_CODE;
  klap20_key = key->key;
  klap20_key->x = NULL;
  klap20_key->y = NULL;
  klap20_key->z0 = NULL;
  klap20_key->z1 = NULL;

  return key;

}

int klap20_mgr_key_free(groupsig_key_t *key) {

  klap20_mgr_key_t *klap20_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "klap20_mgr_key_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_mgr_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    klap20_key = key->key;
    if(klap20_key->x) { pbcext_element_Fr_free(klap20_key->x); klap20_key->x = NULL; }
    if(klap20_key->y) { pbcext_element_Fr_free(klap20_key->y); klap20_key->y = NULL; }
    if(klap20_key->z0) { pbcext_element_Fr_free(klap20_key->z0); klap20_key->z0 = NULL; }
    if(klap20_key->z1) { pbcext_element_Fr_free(klap20_key->z1); klap20_key->z1 = NULL; }
    mem_free(key->key); key->key = NULL;
  }
  
  mem_free(key); key = NULL;

  return IOK;

}

int klap20_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  klap20_mgr_key_t *klap20_dst, *klap20_src;
  int rc;
  
  if(!dst || dst->scheme != GROUPSIG_KLAP20_CODE ||
     !src || src->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_mgr_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  klap20_dst = dst->key;
  klap20_src = src->key;
  rc = IOK;
  
  /* Copy the elements */
  if(klap20_src->x) {
    if(!(klap20_dst->x = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, klap20_mgr_key_copy);
    if(pbcext_element_Fr_set(klap20_dst->x, klap20_src->x) == IERROR)
      GOTOENDRC(IERROR, klap20_mgr_key_copy);
  }

  if(klap20_src->y) {  
    if(!(klap20_dst->y = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, klap20_mgr_key_copy);
    if(pbcext_element_Fr_set(klap20_dst->y, klap20_src->y) == IERROR)
      GOTOENDRC(IERROR, klap20_mgr_key_copy);
  }

  if(klap20_src->z0) {  
    if(!(klap20_dst->z0 = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, klap20_mgr_key_copy);
    if(pbcext_element_Fr_set(klap20_dst->z0, klap20_src->z0) == IERROR)
      GOTOENDRC(IERROR, klap20_mgr_key_copy);
  }

  if(klap20_src->z1) {  
    if(!(klap20_dst->z1 = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, klap20_mgr_key_copy);
    if(pbcext_element_Fr_set(klap20_dst->z1, klap20_src->z1) == IERROR)
      GOTOENDRC(IERROR, klap20_mgr_key_copy);  
  }
    
 klap20_mgr_key_copy_end:

  if(rc == IERROR) {
    if (klap20_dst->x) { pbcext_element_Fr_free(klap20_dst->x); klap20_dst->x = NULL; }
    if (klap20_dst->y) { pbcext_element_Fr_free(klap20_dst->y); klap20_dst->y = NULL; }
    if (klap20_dst->z0) { pbcext_element_Fr_free(klap20_dst->z0); klap20_dst->z0 = NULL; }
    if (klap20_dst->z1) { pbcext_element_Fr_free(klap20_dst->z1); klap20_dst->z1 = NULL; }
  }

  return rc;

}

int klap20_mgr_key_get_size(groupsig_key_t *key) {

  klap20_mgr_key_t *klap20_key;
  uint64_t size64, sx, sy, sz0, sz1;
  
  if(!key || key->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_mgr_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  klap20_key = key->key;

  sx = sy = sz0 = sz1 = 0;

  if (klap20_key->x) { if(pbcext_element_Fr_byte_size(&sx) == IERROR) return -1; }
  if (klap20_key->y) { if(pbcext_element_Fr_byte_size(&sy) == IERROR) return -1; }
  if (klap20_key->z0) { if(pbcext_element_Fr_byte_size(&sz0) == IERROR) return -1; }
  if (klap20_key->z1) { if(pbcext_element_Fr_byte_size(&sz1) == IERROR) return -1; }

  size64 = sizeof(uint8_t)*2 + sizeof(int)*4 + sx + sy + sz0 + sz1;

  if(size64 > INT_MAX) return -1;
  return (int) size64;

}

int klap20_mgr_key_export(byte_t **bytes,
			 uint32_t *size,
			 groupsig_key_t *key) {

  klap20_mgr_key_t *klap20_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;
  uint8_t code, type;  

  if (!bytes ||
      !size ||
      !key || key->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_mgr_key_export", __LINE__, LOGERROR);
    return IERROR;
  }
  
  rc = IOK;
  ctr = 0;
  klap20_key = key->key;
  
  /* Get the number of bytes to represent the key */
  if ((_size = klap20_mgr_key_get_size(key)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }
  
  /* Dump GROUPSIG_KLAP20_CODE */
  code = GROUPSIG_KLAP20_CODE;
  _bytes[ctr++] = code;

  /* Dump key type */
  type = GROUPSIG_KEY_MGRKEY;
  _bytes[ctr++] = GROUPSIG_KEY_MGRKEY;

  /* Dump x */
  __bytes = &_bytes[ctr];
  if (klap20_key->x) {
    if (pbcext_dump_element_Fr_bytes(&__bytes, &len, klap20_key->x) == IERROR) 
      GOTOENDRC(IERROR, klap20_mgr_key_export);
    ctr += len;
  } else {
    ctr += sizeof(int);    
  }

  /* Dump y */
  __bytes = &_bytes[ctr];
  if (klap20_key->y) {
    if (pbcext_dump_element_Fr_bytes(&__bytes, &len, klap20_key->y) == IERROR) 
      GOTOENDRC(IERROR, klap20_mgr_key_export);
    ctr += len;
  } else {
    ctr += sizeof(int);    
  }

  /* Dump z0 */
  if (klap20_key->z0) {  
    __bytes = &_bytes[ctr];
    if (pbcext_dump_element_Fr_bytes(&__bytes, &len, klap20_key->z0) == IERROR) 
      GOTOENDRC(IERROR, klap20_mgr_key_export);
    ctr += len;
  } else {
    ctr += sizeof(int);    
  }
  
  /* Dump z1 */
  if (klap20_key->z1) {
    __bytes = &_bytes[ctr];
    if (pbcext_dump_element_Fr_bytes(&__bytes, &len, klap20_key->z1) == IERROR) 
      GOTOENDRC(IERROR, klap20_mgr_key_export);
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
    LOG_ERRORCODE_MSG(&logger, __FILE__, "klap20_mgr_key_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, klap20_mgr_key_export);
  }

  *size = ctr;  

 klap20_mgr_key_export_end:
  
  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }  

  return rc;
  
}

groupsig_key_t* klap20_mgr_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  klap20_mgr_key_t *klap20_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "klap20_mgr_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;
  
  if(!(key = klap20_mgr_key_init())) {
    return NULL;
  }

  klap20_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "klap20_mgr_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, klap20_mgr_key_import);
  }

  /* Next  byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MGRKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "klap20_mgr_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, klap20_mgr_key_import);
  }

  /* Get x */
  if(!(klap20_key->x = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, klap20_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(klap20_key->x, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klap20_mgr_key_import);

  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(klap20_key->x); klap20_key->x = NULL;
  } else {
    ctr += len;
  }

  /* Get y */
  if(!(klap20_key->y = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, klap20_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(klap20_key->y, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klap20_mgr_key_import);

  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(klap20_key->y); klap20_key->y = NULL;
  } else {
    ctr += len;
  }

  /* Get z0 */
  if(!(klap20_key->z0 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, klap20_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(klap20_key->z0, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klap20_mgr_key_import);

  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(klap20_key->z0); klap20_key->z0 = NULL;
  } else {
    ctr += len;
  }

  /* Get z1 */
  if(!(klap20_key->z1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, klap20_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(klap20_key->z1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klap20_mgr_key_import);

  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(klap20_key->z1); klap20_key->z1 = NULL;
  } else {
    ctr += len;
  }  

 klap20_mgr_key_import_end:
  
  if(rc == IERROR && key) { klap20_mgr_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  
  return NULL; 
  
}

char* klap20_mgr_key_to_string(groupsig_key_t *key) {

  if(!key || key->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_mgr_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  return NULL;

}

/* mgr_key.c ends here */
