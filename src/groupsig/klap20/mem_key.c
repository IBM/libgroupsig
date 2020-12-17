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

#include "klap20.h"
#include "groupsig/klap20/mem_key.h"
#include "shim/base64.h"
#include "shim/pbc_ext.h"
#include "misc/misc.h"
#include "sys/mem.h"

groupsig_key_t* klap20_mem_key_init() {
  
  groupsig_key_t *key;
  klap20_mem_key_t *klap20_key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (klap20_mem_key_t *) mem_malloc(sizeof(klap20_mem_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_KLAP20_CODE;
  klap20_key = key->key;
  
  klap20_key->alpha = NULL;
  klap20_key->u = NULL;
  klap20_key->v = NULL;
  klap20_key->w = NULL;
  
  return key;

}

int klap20_mem_key_free(groupsig_key_t *key) {

  klap20_mem_key_t *klap20_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "klap20_mem_key_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_mem_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    klap20_key = key->key;
    if(klap20_key->alpha) {
      pbcext_element_Fr_free(klap20_key->alpha);
      klap20_key->alpha = NULL;
    }
    if(klap20_key->u) {
      pbcext_element_G1_free(klap20_key->u);
      klap20_key->u = NULL;
    }
    if(klap20_key->v) {
      pbcext_element_G1_free(klap20_key->v);
      klap20_key->v = NULL;
    }
    if(klap20_key->w) {
      pbcext_element_G1_free(klap20_key->w);
      klap20_key->w = NULL;
    }
    mem_free(key->key); key->key = NULL;
    key->key = NULL;
  }
  
  mem_free(key); key = NULL;

  return IOK;

}

int klap20_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  klap20_mem_key_t *klap20_dst, *klap20_src;
  int rc;
  
  if(!dst || dst->scheme != GROUPSIG_KLAP20_CODE ||
     !src || src->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_mem_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  klap20_dst = dst->key;
  klap20_src = src->key;
  rc = IOK;

  /* Copy the elements */
  if(klap20_src->alpha) {
    if(!(klap20_dst->alpha = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, klap20_mem_key_copy);
    if(pbcext_element_Fr_set(klap20_dst->alpha, klap20_src->alpha) == IERROR)
      GOTOENDRC(IERROR, klap20_mem_key_copy);
  }

  if(klap20_src->u) {
    if(!(klap20_dst->u = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, klap20_mem_key_copy); 
    if(pbcext_element_G1_set(klap20_dst->u, klap20_src->u) == IERROR)
      GOTOENDRC(IERROR, klap20_mem_key_copy);
  }

  if(klap20_src->v) {
    if(!(klap20_dst->v = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, klap20_mem_key_copy);
    if(pbcext_element_G1_set(klap20_dst->v, klap20_src->v) == IERROR)
      GOTOENDRC(IERROR, klap20_mem_key_copy);
  }

  if(klap20_src->w) {
    if(!(klap20_dst->w = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, klap20_mem_key_copy);
    if(pbcext_element_G1_set(klap20_dst->w, klap20_src->w) == IERROR)
      GOTOENDRC(IERROR, klap20_mem_key_copy);    
  }
  
 klap20_mem_key_copy_end:

  if(rc == IERROR) {
    if(klap20_dst->alpha) {
      pbcext_element_Fr_free(klap20_dst->alpha);
      klap20_dst->alpha = NULL;
    }
    if(klap20_dst->u) {
      pbcext_element_G1_free(klap20_dst->u);
      klap20_dst->u = NULL;
    }
    if(klap20_dst->v) {
      pbcext_element_G1_free(klap20_dst->v);
      klap20_dst->v = NULL;
    }
    if(klap20_dst->w) {
      pbcext_element_G1_free(klap20_dst->w);
      klap20_dst->w = NULL;
    }
  }

  return rc;

}

int klap20_mem_key_get_size(groupsig_key_t *key) {

  klap20_mem_key_t *klap20_key;
  uint64_t size64, salpha, su, sv, sw;
  
  if(!key || key->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_mem_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  salpha = su = sv = sw = 0;
  klap20_key = key->key;
  
  if(klap20_key->alpha) { if(pbcext_element_Fr_byte_size(&salpha) == IERROR) return -1; }
  if(klap20_key->u) { if(pbcext_element_G1_byte_size(&su) == IERROR) return -1; }
  if(klap20_key->v) { if(pbcext_element_G1_byte_size(&sv) == IERROR) return -1; }
  if(klap20_key->w) { if(pbcext_element_G1_byte_size(&sw) == IERROR) return -1; }

  size64 = sizeof(uint8_t)*2 + sizeof(int)*4+ salpha + su + sv + sw;

  if(size64 > INT_MAX) return -1;
  return (int) size64;

}

int klap20_mem_key_export(byte_t **bytes,
			uint32_t *size,
			groupsig_key_t *key) {

  klap20_mem_key_t *klap20_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;
  uint8_t code, type;  
  
  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_mem_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  klap20_key = key->key;
  
  /* Get the number of bytes to represent the key */
  if ((_size = klap20_mem_key_get_size(key)) == -1) {
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }
  
  /* Dump GROUPSIG_KLAP20_CODE */
  code = GROUPSIG_KLAP20_CODE;
  _bytes[ctr++] = code;

  /* Dump key type */
  type = GROUPSIG_KEY_MEMKEY;
  _bytes[ctr++] = GROUPSIG_KEY_MEMKEY;
  
  /* Dump alpha */
  if (klap20_key->alpha) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, klap20_key->alpha) == IERROR) 
      GOTOENDRC(IERROR, klap20_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump u */
  if (klap20_key->u) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, klap20_key->u) == IERROR)
      GOTOENDRC(IERROR, klap20_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump v */
  if (klap20_key->v) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, klap20_key->v) == IERROR)
      GOTOENDRC(IERROR, klap20_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }
  

  /* Dump w */
  if (klap20_key->w) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, klap20_key->w) == IERROR) 
      GOTOENDRC(IERROR, klap20_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "klap20_mem_key_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, klap20_mem_key_export);
  }  

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }
  
  *size = ctr;  
  
 klap20_mem_key_export_end:
  
  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }  

  return rc;
  
}

groupsig_key_t* klap20_mem_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  klap20_mem_key_t *klap20_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "klap20_mem_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;
  
  if(!(key = klap20_mem_key_init())) {
    return NULL;
  }

  klap20_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "klap20_mem_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, klap20_mem_key_import);
  }

  /* Next  byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MEMKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "klap20_mem_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, klap20_mem_key_import);
  }

  /* Get alpha */
  if(!(klap20_key->alpha = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, klap20_mem_key_import);
  if(pbcext_get_element_Fr_bytes(klap20_key->alpha, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klap20_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(klap20_key->alpha); klap20_key->alpha = NULL;
  } else {
    ctr += len;
  }

  /* Get u */
  if(!(klap20_key->u = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klap20_mem_key_import);
  if(pbcext_get_element_G1_bytes(klap20_key->u, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klap20_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(klap20_key->u); klap20_key->u = NULL;
  } else {
    ctr += len;
  }

  /* Get v */  
  if(!(klap20_key->v = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klap20_mem_key_import);
  if(pbcext_get_element_G1_bytes(klap20_key->v, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klap20_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(klap20_key->v); klap20_key->v = NULL;
  } else {
    ctr += len;
  }  

  /* Get w */
  if(!(klap20_key->w = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klap20_mem_key_import);
  if(pbcext_get_element_G1_bytes(klap20_key->w, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klap20_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(klap20_key->w); klap20_key->w = NULL;
  } else {
    ctr += len;
  }  
 

 klap20_mem_key_import_end:
  
  if(rc == IERROR && key) { klap20_mem_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  
  return NULL; 
}

char* klap20_mem_key_to_string(groupsig_key_t *key) {

  if(!key || key->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_mem_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  return NULL;

}

/* mem_key.c ends here */
