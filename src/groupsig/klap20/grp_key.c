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

#include "klap20.h"
#include "groupsig/klap20/grp_key.h"

groupsig_key_t* klap20_grp_key_init() {

  groupsig_key_t *key;
  klap20_grp_key_t *klap20_key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (klap20_grp_key_t *) mem_malloc(sizeof(klap20_grp_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_KLAP20_CODE;
  klap20_key = key->key;
  klap20_key->g = NULL;
  klap20_key->gg = NULL;
  klap20_key->XX = NULL;
  klap20_key->YY = NULL;
  klap20_key->ZZ0 = NULL;
  klap20_key->ZZ1 = NULL;
  
  return key;
  
}

int klap20_grp_key_free(groupsig_key_t *key) {

  klap20_grp_key_t *klap20_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "klap20_grp_key_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_grp_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    klap20_key = key->key;
    if(klap20_key->g) { pbcext_element_G1_free(klap20_key->g); klap20_key->g = NULL; }
    if(klap20_key->gg) { pbcext_element_G2_free(klap20_key->gg); klap20_key->gg = NULL; }
    if(klap20_key->XX) { pbcext_element_G2_free(klap20_key->XX); klap20_key->XX = NULL; }
    if(klap20_key->YY) { pbcext_element_G2_free(klap20_key->YY); klap20_key->YY = NULL; }
    if(klap20_key->ZZ0) { pbcext_element_G2_free(klap20_key->ZZ0); klap20_key->ZZ0 = NULL; }
    if(klap20_key->ZZ1) { pbcext_element_G2_free(klap20_key->ZZ1); klap20_key->ZZ1 = NULL; }    
    mem_free(key->key); key->key = NULL;
  }

  mem_free(key); key = NULL;

  return IOK;

}

int klap20_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  klap20_grp_key_t *klap20_dst, *klap20_src;
  int rc;
  
  if(!dst || dst->scheme != GROUPSIG_KLAP20_CODE ||
     !src || src->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_grp_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  klap20_dst = dst->key;
  klap20_src = src->key;
  rc = IOK;

  /* Copy the elements */
  if(!(klap20_dst->g = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klap20_grp_key_copy);
  if(pbcext_element_G1_set(klap20_dst->g, klap20_src->g) == IERROR)
    GOTOENDRC(IERROR, klap20_grp_key_copy);
  if(!(klap20_dst->gg = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_grp_key_copy);  
  if(pbcext_element_G2_set(klap20_dst->gg, klap20_src->gg) == IERROR)
    GOTOENDRC(IERROR, klap20_grp_key_copy);
  if(!(klap20_dst->XX = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_grp_key_copy);  
  if(pbcext_element_G2_set(klap20_dst->XX, klap20_src->XX) == IERROR)
    GOTOENDRC(IERROR, klap20_grp_key_copy);
  if(!(klap20_dst->YY = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_grp_key_copy);  
  if(pbcext_element_G2_set(klap20_dst->YY, klap20_src->YY) == IERROR)
    GOTOENDRC(IERROR, klap20_grp_key_copy);
  if(!(klap20_dst->ZZ0 = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_grp_key_copy);  
  if(pbcext_element_G2_set(klap20_dst->ZZ0, klap20_src->ZZ0) == IERROR)
    GOTOENDRC(IERROR, klap20_grp_key_copy);
  if(!(klap20_dst->ZZ1 = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_grp_key_copy);  
  if(pbcext_element_G2_set(klap20_dst->ZZ1, klap20_src->ZZ1) == IERROR)
    GOTOENDRC(IERROR, klap20_grp_key_copy);  

 klap20_grp_key_copy_end:

  if(rc == IERROR) {
    if (klap20_dst->g) { pbcext_element_G1_free(klap20_dst->g); klap20_dst->g = NULL; }
    if (klap20_dst->gg) { pbcext_element_G2_free(klap20_dst->gg); klap20_dst->gg = NULL; }
    if (klap20_dst->XX) { pbcext_element_G2_free(klap20_dst->XX); klap20_dst->XX = NULL; }
    if (klap20_dst->YY) { pbcext_element_G2_free(klap20_dst->YY); klap20_dst->YY = NULL; }
    if (klap20_dst->ZZ0) { pbcext_element_G2_free(klap20_dst->ZZ0); klap20_dst->ZZ0 = NULL; }
    if (klap20_dst->ZZ1) { pbcext_element_G2_free(klap20_dst->ZZ1); klap20_dst->ZZ1 = NULL; }
  }
  
  return rc;

}

int klap20_grp_key_get_size(groupsig_key_t *key) {

  klap20_grp_key_t *klap20_key;
  uint64_t size64, sg, sgg, sXX, sYY, sZZ0, sZZ1;
  
  if(!key || key->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_grp_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  sg = sgg = sXX = sYY = sZZ0 = sZZ1 = 0;

  klap20_key = key->key;

  if(pbcext_element_G1_byte_size(&sg) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sgg) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sXX) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sYY) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sZZ0) == IERROR) return -1;
  if(pbcext_element_G2_byte_size(&sZZ1) == IERROR) return -1;  

  size64 = sizeof(uint8_t)*2 + sizeof(int)*6 + sg + sgg + sXX + sYY + sZZ0 + sZZ1;
  if (size64 > INT_MAX) return -1;
  
  return (int) size64;  

}

int klap20_grp_key_export(byte_t **bytes,
			 uint32_t *size,
			 groupsig_key_t *key) {

  klap20_grp_key_t *klap20_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;
  uint8_t code, type;  

  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_grp_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  klap20_key = key->key;
  
  /* Get the number of bytes to represent the key */
  if ((_size = klap20_grp_key_get_size(key)) == -1) {
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }
  
  /* Dump GROUPSIG_KLAP20_CODE */
  code = GROUPSIG_KLAP20_CODE;
  _bytes[ctr++] = code;

  /* Dump key type */
  type = GROUPSIG_KEY_GRPKEY;
  _bytes[ctr++] = GROUPSIG_KEY_GRPKEY;

  /* Dump g */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, klap20_key->g) == IERROR) 
    GOTOENDRC(IERROR, klap20_grp_key_export);
  ctr += len;
  
  /* Dump gg */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, klap20_key->gg) == IERROR)
    GOTOENDRC(IERROR, klap20_grp_key_export);
  ctr += len;
  
  /* Dump XX */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, klap20_key->XX) == IERROR)
    GOTOENDRC(IERROR, klap20_grp_key_export);
  ctr += len;

  /* Dump YY */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, klap20_key->YY) == IERROR)    
    GOTOENDRC(IERROR, klap20_grp_key_export);
  ctr += len;

  /* Dump XX */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, klap20_key->ZZ0) == IERROR)
    GOTOENDRC(IERROR, klap20_grp_key_export);
  ctr += len;

  /* Dump YY */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_G2_bytes(&__bytes, &len, klap20_key->ZZ1) == IERROR)
    GOTOENDRC(IERROR, klap20_grp_key_export);
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
    LOG_ERRORCODE_MSG(&logger, __FILE__, "klap20_grp_key_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, klap20_grp_key_export);
  }

  *size = ctr;  
  
 klap20_grp_key_export_end:

  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }
  
  return rc;
  
}

groupsig_key_t* klap20_grp_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  klap20_grp_key_t *klap20_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "klap20_grp_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;
  
  if(!(key = klap20_grp_key_init())) {
    return NULL;
  }

  klap20_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "klap20_grp_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, klap20_grp_key_import);
  }

  /* Next  byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_GRPKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "klap20_grp_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, klap20_grp_key_import);
  }

  /* Get g */
  if(!(klap20_key->g = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klap20_grp_key_import);
  if(pbcext_get_element_G1_bytes(klap20_key->g, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klap20_grp_key_import);
  ctr += len;  

  /* Get gg */
  if(!(klap20_key->gg = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_grp_key_import);
  if(pbcext_get_element_G2_bytes(klap20_key->gg, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klap20_grp_key_import);
  ctr += len;  

  /* Get XX */
  if(!(klap20_key->XX = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_grp_key_import);
  if(pbcext_get_element_G2_bytes(klap20_key->XX, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klap20_grp_key_import);
  ctr += len;  

  /* Get YY */
  if(!(klap20_key->YY = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_grp_key_import);
  if(pbcext_get_element_G2_bytes(klap20_key->YY, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klap20_grp_key_import);
  ctr += len;

  /* Get ZZ0 */
  if(!(klap20_key->ZZ0 = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_grp_key_import);
  if(pbcext_get_element_G2_bytes(klap20_key->ZZ0, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klap20_grp_key_import);
  ctr += len;  

  /* Get ZZ1 */
  if(!(klap20_key->ZZ1 = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, klap20_grp_key_import);
  if(pbcext_get_element_G2_bytes(klap20_key->ZZ1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klap20_grp_key_import);
  ctr += len;  
  
 klap20_grp_key_import_end:
  
  if(rc == IERROR && key) { klap20_grp_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  
  return NULL; 
  
}

char* klap20_grp_key_to_string(groupsig_key_t *key) { 
  return NULL;
}

/* grp_key.c ends here */
