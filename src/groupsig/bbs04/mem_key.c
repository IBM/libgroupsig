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
#include <math.h>

#include "bbs04.h"
#include "groupsig/bbs04/mem_key.h"
#include "shim/base64.h"
#include "shim/pbc_ext.h"
#include "misc/misc.h"
#include "sys/mem.h"

groupsig_key_t* bbs04_mem_key_init() {
  
  groupsig_key_t *key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (bbs04_mem_key_t *) mem_malloc(sizeof(bbs04_mem_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_BBS04_CODE;

  return key;

}

int bbs04_mem_key_free(groupsig_key_t *key) {

  bbs04_mem_key_t *bbs04_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "bbs04_mem_key_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_mem_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    bbs04_key = key->key;
    if(bbs04_key->x) { pbcext_element_Fr_free(bbs04_key->x); bbs04_key->x = NULL; }
    if(bbs04_key->A) { pbcext_element_G1_free(bbs04_key->A); bbs04_key->A = NULL; }
    if(bbs04_key->Ag2) { pbcext_element_GT_free(bbs04_key->Ag2); bbs04_key->Ag2 = NULL; }
    mem_free(key->key); key->key = NULL;
    key->key = NULL;
  }
  
  mem_free(key); key = NULL;

  return IOK;

}

int bbs04_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  bbs04_mem_key_t *bbs04_dst, *bbs04_src;
  int rc;
  
  if(!dst || dst->scheme != GROUPSIG_BBS04_CODE ||
     !src || src->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_mem_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  bbs04_dst = dst->key;
  bbs04_src = src->key;
  rc = IOK;

  /* Copy the elements */
  if(!(bbs04_dst->x = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_mem_key_copy);
  if(pbcext_element_Fr_set(bbs04_dst->x, bbs04_src->x) == IERROR)
    GOTOENDRC(IERROR, bbs04_mem_key_copy);    
  if(!(bbs04_dst->A = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bbs04_mem_key_copy); 
  if(pbcext_element_G1_set(bbs04_dst->A, bbs04_src->A) == IERROR)
    GOTOENDRC(IERROR, bbs04_mem_key_copy);
  if(!(bbs04_dst->Ag2 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, bbs04_mem_key_copy);
  if(pbcext_element_GT_set(bbs04_dst->Ag2, bbs04_src->Ag2) == IERROR)
    GOTOENDRC(IERROR, bbs04_mem_key_copy);  

 bbs04_mem_key_copy_end:

  if(rc == IERROR) {
    if(bbs04_dst->x) { pbcext_element_Fr_free(bbs04_dst->x); bbs04_dst->x = NULL; }
    if(bbs04_dst->A) { pbcext_element_G1_free(bbs04_dst->A); bbs04_dst->A = NULL; }
    if(bbs04_dst->Ag2) { pbcext_element_GT_free(bbs04_dst->Ag2); bbs04_dst->Ag2 = NULL; }
  }

  return rc;

}

int bbs04_mem_key_get_size(groupsig_key_t *key) {

  bbs04_mem_key_t *bbs04_key;
  uint64_t size64, sx, sA, sAg2;
  
  if(!key || key->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_mem_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  if(pbcext_element_Fr_byte_size(&sx) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sA) == IERROR) return -1;
  if(pbcext_element_GT_byte_size(&sAg2) == IERROR) return -1;

  size64 = sizeof(uint8_t)*2 + sizeof(int)*3+ sx + sA + sAg2;

  if(size64 > INT_MAX) return -1;
  return (int) size64;

}

int bbs04_mem_key_export(byte_t **bytes,
			 uint32_t *size,
			 groupsig_key_t *key) {

  bbs04_mem_key_t *bbs04_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;
  uint8_t code, type;  
  
  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_mem_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  bbs04_key = key->key;
  
  /* Get the number of bytes to represent the key */
  if ((_size = bbs04_mem_key_get_size(key)) == -1) {
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }
  
  /* Dump GROUPSIG_BBS04_CODE */
  code = GROUPSIG_BBS04_CODE;
  _bytes[ctr++] = code;

  /* Dump key type */
  type = GROUPSIG_KEY_MEMKEY;
  _bytes[ctr++] = GROUPSIG_KEY_MEMKEY;
  
  /* Dump x */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bbs04_key->x) == IERROR) 
    GOTOENDRC(IERROR, bbs04_mem_key_export);
  ctr += len;  

  /* Dump A */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, bbs04_key->A) == IERROR) 
    GOTOENDRC(IERROR, bbs04_mem_key_export);
  ctr += len;

  /* Dump e(A, g2) */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_GT_bytes(&__bytes, &len, bbs04_key->Ag2) == IERROR) 
    GOTOENDRC(IERROR, bbs04_mem_key_export);
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
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bbs04_mem_key_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, bbs04_mem_key_export);
  }

  *size = ctr;  
  
 bbs04_mem_key_export_end:
  
  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }  

  return rc;
  
}

groupsig_key_t* bbs04_mem_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  bbs04_mem_key_t *bbs04_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_mem_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;
  
  if(!(key = bbs04_mem_key_init())) {
    return NULL;
  }

  bbs04_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bbs04_mem_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, bbs04_mem_key_import);
  }

  /* Next  byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MEMKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bbs04_mem_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, bbs04_mem_key_import);
  }

  /* Get x */
  if(!(bbs04_key->x = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_mem_key_import);
  if(pbcext_get_element_Fr_bytes(bbs04_key->x, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bbs04_mem_key_import);
  ctr += len;  

  /* Get A */
  if(!(bbs04_key->A = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bbs04_mem_key_import);
  if(pbcext_get_element_G1_bytes(bbs04_key->A, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bbs04_mem_key_import);
  ctr += len;  

  /* Get Ag2 */
  if(!(bbs04_key->Ag2 = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, bbs04_mem_key_import);
  if(pbcext_get_element_GT_bytes(bbs04_key->Ag2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bbs04_mem_key_import);
  ctr += len;    

 bbs04_mem_key_import_end:
  
  if(rc == IERROR && key) { bbs04_mem_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  
  return NULL; 
}

char* bbs04_mem_key_to_string(groupsig_key_t *key) {

  if(!key || key->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_mem_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  return NULL;

}

/* mem_key.c ends here */
