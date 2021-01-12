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

#include "sysenv.h"
#include "sys/mem.h"
#include "misc/misc.h"
#include "shim/base64.h"
#include "shim/pbc_ext.h"

#include "ps16.h"
#include "groupsig/ps16/grp_key.h"

groupsig_key_t* ps16_grp_key_init() {

  groupsig_key_t *key;
  ps16_grp_key_t *ps16_key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (ps16_grp_key_t *) mem_malloc(sizeof(ps16_grp_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_PS16_CODE;
  ps16_key = key->key;
  ps16_key->g = NULL;
  ps16_key->gg = NULL;
  ps16_key->X = NULL;
  ps16_key->Y = NULL;
  
  return key;
  
}

int ps16_grp_key_free(groupsig_key_t *key) {

  ps16_grp_key_t *ps16_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "ps16_grp_key_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_grp_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    ps16_key = key->key;
    if(ps16_key->g) { pbcext_element_G1_free(ps16_key->g); ps16_key->g = NULL; }
    if(ps16_key->gg) { pbcext_element_G2_free(ps16_key->gg); ps16_key->gg = NULL; }
    if(ps16_key->X) { pbcext_element_G2_free(ps16_key->X); ps16_key->X = NULL; }
    if(ps16_key->Y) { pbcext_element_G2_free(ps16_key->Y); ps16_key->Y = NULL; }
    mem_free(key->key); key->key = NULL;
  }

  mem_free(key); key = NULL;

  return IOK;

}

int ps16_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  ps16_grp_key_t *ps16_dst, *ps16_src;
  int rc;
  
  if(!dst || dst->scheme != GROUPSIG_PS16_CODE ||
     !src || src->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_grp_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  ps16_dst = dst->key;
  ps16_src = src->key;
  rc = IOK;

  /* Copy the elements */
  if(!(ps16_dst->g = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ps16_grp_key_copy);
  if(pbcext_element_G1_set(ps16_dst->g, ps16_src->g) == IERROR)
    GOTOENDRC(IERROR, ps16_grp_key_copy);
  if(!(ps16_dst->gg = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, ps16_grp_key_copy);  
  if(pbcext_element_G2_set(ps16_dst->gg, ps16_src->gg) == IERROR)
    GOTOENDRC(IERROR, ps16_grp_key_copy);
  if(!(ps16_dst->X = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, ps16_grp_key_copy);  
  if(pbcext_element_G2_set(ps16_dst->X, ps16_src->X) == IERROR)
    GOTOENDRC(IERROR, ps16_grp_key_copy);
  if(!(ps16_dst->Y = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, ps16_grp_key_copy);  
  if(pbcext_element_G2_set(ps16_dst->Y, ps16_src->Y) == IERROR)
    GOTOENDRC(IERROR, ps16_grp_key_copy);  

 ps16_grp_key_copy_end:

  if(rc == IERROR) {
    if (ps16_dst->g) { pbcext_element_G1_free(ps16_dst->g); ps16_dst->g = NULL; }
    if (ps16_dst->gg) { pbcext_element_G2_free(ps16_dst->gg); ps16_dst->gg = NULL; }
    if (ps16_dst->X) { pbcext_element_G2_free(ps16_dst->X); ps16_dst->X = NULL; }
    if (ps16_dst->Y) { pbcext_element_G2_free(ps16_dst->Y); ps16_dst->Y = NULL; }
  }
  
  return rc;

}

int ps16_grp_key_get_size(groupsig_key_t *key) {

  ps16_grp_key_t *ps16_key;
  uint64_t size64, sg, sgg, sX, sY;
  
  if(!key || key->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_grp_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  ps16_key = key->key;

  sg = sgg = sX = sY = 0;

  if(pbcext_element_G1_byte_size(&sg) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sgg) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sX) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sY) == IERROR) return -1;

  size64 = sizeof(uint8_t)*2 + sizeof(int)*4 + sg + sgg + sX + sY;
  if (size64 > INT_MAX) return -1;
  
  return (int) size64;  

}

int ps16_grp_key_export(byte_t **bytes,
			 uint32_t *size,
			 groupsig_key_t *key) {

  ps16_grp_key_t *ps16_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;
  uint8_t code, type;  

  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_grp_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  ps16_key = key->key;
  
  /* Get the number of bytes to represent the key */
  if ((_size = ps16_grp_key_get_size(key)) == -1) {
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }
  
  /* Dump GROUPSIG_PS16_CODE */
  code = GROUPSIG_PS16_CODE;
  _bytes[ctr++] = code;

  /* Dump key type */
  type = GROUPSIG_KEY_GRPKEY;
  _bytes[ctr++] = GROUPSIG_KEY_GRPKEY;

  /* Dump g */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, ps16_key->g) == IERROR) 
    GOTOENDRC(IERROR, ps16_grp_key_export);
  ctr += len;
  
  /* Dump gg */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, ps16_key->gg) == IERROR)
    GOTOENDRC(IERROR, ps16_grp_key_export);
  ctr += len;
  
  /* Dump X */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, ps16_key->X) == IERROR)
    GOTOENDRC(IERROR, ps16_grp_key_export);
  ctr += len;

  /* Dump Y */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, ps16_key->Y) == IERROR)    
    GOTOENDRC(IERROR, ps16_grp_key_export);
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
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ps16_grp_key_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, ps16_grp_key_export);
  }

  *size = ctr;  
  
 ps16_grp_key_export_end:

  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }
  
  return rc;
  
}

groupsig_key_t* ps16_grp_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  ps16_grp_key_t *ps16_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "ps16_grp_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;
  
  if(!(key = ps16_grp_key_init())) {
    return NULL;
  }

  ps16_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ps16_grp_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, ps16_grp_key_import);
  }

  /* Next  byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_GRPKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ps16_grp_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, ps16_grp_key_import);
  }

  /* Get g */
  if(!(ps16_key->g = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ps16_grp_key_import);
  if(pbcext_get_element_G1_bytes(ps16_key->g, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ps16_grp_key_import);
  ctr += len;  

  /* Get gg */
  if(!(ps16_key->gg = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, ps16_grp_key_import);
  if(pbcext_get_element_G2_bytes(ps16_key->gg, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ps16_grp_key_import);
  ctr += len;  

  /* Get X */
  if(!(ps16_key->X = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, ps16_grp_key_import);
  if(pbcext_get_element_G2_bytes(ps16_key->X, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ps16_grp_key_import);
  ctr += len;  

  /* Get Y */
  if(!(ps16_key->Y = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, ps16_grp_key_import);
  if(pbcext_get_element_G2_bytes(ps16_key->Y, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ps16_grp_key_import);
  ctr += len;  
  
 ps16_grp_key_import_end:
  
  if(rc == IERROR && key) { ps16_grp_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  
  return NULL; 
  
}

char* ps16_grp_key_to_string(groupsig_key_t *key) { 
  return NULL;
}

/* grp_key.c ends here */
