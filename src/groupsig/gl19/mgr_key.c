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

#include "gl19.h"
#include "logger.h"
#include "groupsig/gl19/mgr_key.h"
#include "misc/misc.h"
#include "shim/base64.h"
#include "sys/mem.h"

groupsig_key_t* gl19_mgr_key_init() {

  groupsig_key_t *key;
  gl19_mgr_key_t *gl19_key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (gl19_mgr_key_t *) mem_malloc(sizeof(gl19_mgr_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_GL19_CODE;
  gl19_key = key->key;
  gl19_key->isk = NULL;
  gl19_key->csk = NULL;
  gl19_key->esk = NULL;  

  return key;

}

int gl19_mgr_key_free(groupsig_key_t *key) {

  gl19_mgr_key_t *gl19_key;
  
 if(key->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_mgr_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    gl19_key = key->key;
    if(gl19_key->isk) { pbcext_element_Fr_free(gl19_key->isk); gl19_key->isk = NULL; }
    if(gl19_key->csk) { pbcext_element_Fr_free(gl19_key->csk); gl19_key->csk = NULL; }
    if(gl19_key->esk) { pbcext_element_Fr_free(gl19_key->esk); gl19_key->esk = NULL; }
    mem_free(key->key); key->key = NULL;
  }
  
  mem_free(key);
  
  return IOK;

}

int gl19_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  gl19_mgr_key_t *gl19_dst, *gl19_src;
  int rc;

  if(!dst || dst->scheme != GROUPSIG_GL19_CODE ||
     !src || src->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_mgr_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  gl19_dst = dst->key;
  gl19_src = src->key;
  rc = IOK;
  
  /* Copy the elements */
  if(gl19_dst->isk) {
    if(!(gl19_dst->isk = pbcext_element_Fr_init())) return IERROR;
    if(pbcext_element_Fr_set(gl19_dst->isk, gl19_src->isk) == IERROR)
      GOTOENDRC(IERROR, gl19_mgr_key_copy);
  }

  if(gl19_dst->csk) {
    if(!(gl19_dst->csk = pbcext_element_Fr_init())) 
      GOTOENDRC(IERROR, gl19_mgr_key_copy);          
    if(pbcext_element_Fr_set(gl19_dst->csk, gl19_src->csk) == IERROR)
      GOTOENDRC(IERROR, gl19_mgr_key_copy);            
  }

 gl19_mgr_key_copy_end:

  if (rc == IERROR) {
    if (gl19_dst->isk) { pbcext_element_Fr_free(gl19_dst->isk); gl19_dst->isk = NULL; }
    if (gl19_dst->csk) { pbcext_element_Fr_free(gl19_dst->csk); gl19_dst->csk = NULL; }
    if (gl19_dst->esk) { pbcext_element_Fr_free(gl19_dst->esk); gl19_dst->esk = NULL; }
  }

  return rc;

}

int gl19_mgr_key_get_size(groupsig_key_t *key) {

  gl19_mgr_key_t *gl19_key;
  uint64_t sisk, scsk, sesk;
  int size;
  
  if(!key || key->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_mgr_key_get_size",
	       __LINE__, LOGERROR);
    return -1;
  }

  gl19_key = key->key;
  sisk = scsk = sesk = 0;
  
  if(gl19_key->isk) { if(pbcext_element_Fr_byte_size(&sisk) == IERROR) return -1; }
  if(gl19_key->csk) { if(pbcext_element_Fr_byte_size(&scsk) == IERROR) return -1; }
  if(gl19_key->esk) { if(pbcext_element_Fr_byte_size(&sesk) == IERROR) return -1; }

  if(sisk + scsk + sesk + sizeof(int)*3+2 > INT_MAX) return -1;
  size = (int) (sisk + scsk + sesk + sizeof(int)*3+2);

  return size;

}

int gl19_mgr_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key) {

  gl19_mgr_key_t *gl19_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  uint32_t _size;
  int ctr, rc;
  
  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_mgr_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  gl19_key = key->key;

  if ((_size = gl19_mgr_key_get_size(key)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }

  /* Dump GROUPSIG_GL19_CODE */
  _bytes[ctr++] = GROUPSIG_GL19_CODE;
  
  /* Dump key type */
  _bytes[ctr++] = GROUPSIG_KEY_MGRKEY;

  /* Dump isk, if present (Issuer key) */
  if(gl19_key->isk) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, gl19_key->isk) == IERROR)
      GOTOENDRC(IERROR, gl19_mgr_key_export);
    ctr += len;
  } else {
    ctr += sizeof(int);
  }

  /* Dump csk, if present (Converter key) */
  if(gl19_key->csk) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, gl19_key->csk) == IERROR)
      GOTOENDRC(IERROR, gl19_mgr_key_export);
    ctr += len;
  } else {
    ctr += sizeof(int);
  }

  /* Dump esk, if present (Extractor's key) */
  if(gl19_key->esk) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, gl19_key->esk) == IERROR)
      GOTOENDRC(IERROR, gl19_mgr_key_export);
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
    LOG_ERRORCODE_MSG(&logger, __FILE__, "gl19_mgr_key_export", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, gl19_mgr_key_export);
  }

  *size = ctr;

 gl19_mgr_key_export_end:

  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  
  return rc;
  
}

groupsig_key_t* gl19_mgr_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  gl19_mgr_key_t *gl19_key;
  uint64_t len;
  int rc, ctr;
  uint8_t type, scheme;  
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "gl19_mgr_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(key = gl19_mgr_key_init())) {
    return NULL;
  }
  gl19_key = key->key;    

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "gl19_mgr_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, gl19_mgr_key_import);
  }  

  /* Next byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MGRKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "gl19_mgr_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, gl19_mgr_key_import);
  }  

  /* Get isk */
  if(!(gl19_key->isk = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, gl19_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(gl19_key->isk, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_mgr_key_import);

  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(gl19_key->isk); gl19_key->isk = NULL;
  } else {
    ctr += len;
  }

  /* Get csk */
  if(!(gl19_key->csk = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, gl19_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(gl19_key->csk, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_mgr_key_import);

  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(gl19_key->csk); gl19_key->csk = NULL;
  } else {
    ctr += len;
  }

  /* Get esk */
  if(!(gl19_key->esk = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, gl19_mgr_key_import);
  if(pbcext_get_element_Fr_bytes(gl19_key->esk, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_mgr_key_import);

  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(gl19_key->esk); gl19_key->esk = NULL;
  } else {
    ctr += len;
  }  

 gl19_mgr_key_import_end:
  
  if(rc == IERROR && key) { gl19_mgr_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  return NULL;

}

char* gl19_mgr_key_to_string(groupsig_key_t *key) {

  if(!key || key->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_mgr_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  return NULL;

}

/* mgr_key.c ends here */
