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

#include "bbs04.h"
#include "groupsig/bbs04/mgr_key.h"
#include "misc/misc.h"
#include "shim/base64.h"
#include "shim/pbc_ext.h"
#include "sys/mem.h"

groupsig_key_t* bbs04_mgr_key_init() {

  groupsig_key_t *key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (bbs04_mgr_key_t *) mem_malloc(sizeof(bbs04_mgr_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_BBS04_CODE;

  return key;

}

int bbs04_mgr_key_free(groupsig_key_t *key) {

  bbs04_mgr_key_t *bbs04_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "bbs04_mgr_key_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_mgr_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    bbs04_key = key->key;
    if(bbs04_key->xi1) { pbcext_element_Fr_free(bbs04_key->xi1); bbs04_key->xi1 = NULL; }
    if(bbs04_key->xi2) { pbcext_element_Fr_free(bbs04_key->xi2); bbs04_key->xi2 = NULL; }
    if(bbs04_key->gamma) { pbcext_element_Fr_free(bbs04_key->gamma); bbs04_key->gamma = NULL; }
    mem_free(key->key); key->key = NULL;
  }
  
  mem_free(key); key = NULL;

  return IOK;

}

int bbs04_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  bbs04_mgr_key_t *bbs04_dst, *bbs04_src;
  int rc;
  
  if(!dst || dst->scheme != GROUPSIG_BBS04_CODE ||
     !src || src->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_mgr_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  bbs04_dst = dst->key;
  bbs04_src = src->key;
  rc = IOK;
  
  /* Copy the elements */
  if(!(bbs04_dst->xi1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_mgr_key_copy);
  if(pbcext_element_Fr_set(bbs04_dst->xi1, bbs04_src->xi1) == IERROR)
    GOTOENDRC(IERROR, bbs04_mgr_key_copy);
  if(!(bbs04_dst->xi2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_mgr_key_copy);
  if(pbcext_element_Fr_set(bbs04_dst->xi2, bbs04_src->xi2) == IERROR)
    GOTOENDRC(IERROR, bbs04_mgr_key_copy);
  if(!(bbs04_dst->gamma = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_mgr_key_copy);
  if(pbcext_element_Fr_set(bbs04_dst->gamma, bbs04_src->gamma) == IERROR)
    GOTOENDRC(IERROR, bbs04_mgr_key_copy);

 bbs04_mgr_key_copy_end:

  if(rc == IERROR) {
    if (bbs04_dst->xi1) { pbcext_element_Fr_free(bbs04_dst->xi1); bbs04_dst->xi1 = NULL; }
    if (bbs04_dst->xi2) { pbcext_element_Fr_free(bbs04_dst->xi2); bbs04_dst->xi2 = NULL; }
    if (bbs04_dst->gamma) { pbcext_element_Fr_free(bbs04_dst->gamma); bbs04_dst->gamma = NULL; }
  }

  return rc;

}

int bbs04_mgr_key_get_size(groupsig_key_t *key) {

  bbs04_mgr_key_t *bbs04_key;
  uint64_t size64, sxi1, sxi2, sgamma;
  
  if(!key || key->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_mgr_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  if(pbcext_element_Fr_byte_size(&sxi1) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sxi2) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sgamma) == IERROR) return -1;

  size64 = sizeof(uint8_t)*2 + sizeof(int)*3 + sxi1 + sxi2 + sgamma;

  if(size64 > INT_MAX) return -1;
  return (int) size64;

}

int bbs04_mgr_key_export(byte_t **bytes,
			 uint32_t *size,
			 groupsig_key_t *key) {

  bbs04_mgr_key_t *bbs04_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;
  uint8_t code, type;  

  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_mgr_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  bbs04_key = key->key;
  
  /* Get the number of bytes to represent the key */
  if ((_size = bbs04_mgr_key_get_size(key)) == -1) {
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }
  
  /* Dump GROUPSIG_BBS04_CODE */
  code = GROUPSIG_BBS04_CODE;
  _bytes[ctr++] = code;

  /* Dump key type */
  type = GROUPSIG_KEY_MGRKEY;
  _bytes[ctr++] = GROUPSIG_KEY_MGRKEY;

  /* Dump xi1 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bbs04_key->xi1) == IERROR) 
    GOTOENDRC(IERROR, bbs04_mgr_key_export);
  ctr += len;

  /* Dump xi2 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bbs04_key->xi2) == IERROR) 
    GOTOENDRC(IERROR, bbs04_mgr_key_export);
  ctr += len;

  /* Dump gamma */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bbs04_key->gamma) == IERROR) 
    GOTOENDRC(IERROR, bbs04_mgr_key_export);
  ctr += len;

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bbs04_mgr_key_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, bbs04_mgr_key_export);
  }

  *size = ctr;  

 bbs04_mgr_key_export_end:
  
  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }  

  return rc;
  
}

groupsig_key_t* bbs04_mgr_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  bbs04_mgr_key_t *bbs04_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_mgr_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;
  
  if(!(key = bbs04_mgr_key_init())) {
    return NULL;
  }

  bbs04_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bbs04_mgr_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, bbs04_mgr_key_import);
  }

  /* Next  byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MGRKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bbs04_mgr_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, bbs04_mgr_key_import);
  }

  /* Get xi1 */
  if(!(bbs04_key->xi1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(bbs04_key->xi1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bbs04_mgr_key_import);
  ctr += len;

  /* Get xi2 */
  if(!(bbs04_key->xi2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(bbs04_key->xi2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bbs04_mgr_key_import);
  ctr += len;

  /* Get gamma */
  if(!(bbs04_key->gamma = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(bbs04_key->gamma, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bbs04_mgr_key_import);
  ctr += len;  

 bbs04_mgr_key_import_end:
  
  if(rc == IERROR && key) { bbs04_mgr_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  
  return NULL; 
  
}

char* bbs04_mgr_key_to_string(groupsig_key_t *key) {

  if(!key || key->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_mgr_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  return NULL;

}

/* mgr_key.c ends here */
