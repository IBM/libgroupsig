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

#include "ps16.h"
#include "groupsig/ps16/mem_key.h"
#include "shim/base64.h"
#include "shim/pbc_ext.h"
#include "misc/misc.h"
#include "sys/mem.h"

groupsig_key_t* ps16_mem_key_init() {
  
  groupsig_key_t *key;
  ps16_mem_key_t *ps16_key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (ps16_mem_key_t *) mem_malloc(sizeof(ps16_mem_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_PS16_CODE;
  ps16_key = key->key;
  
  ps16_key->sk = NULL;
  ps16_key->sigma1 = NULL;
  ps16_key->sigma2 = NULL;
  ps16_key->e = NULL;
  
  return key;

}

int ps16_mem_key_free(groupsig_key_t *key) {

  ps16_mem_key_t *ps16_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "ps16_mem_key_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_mem_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    ps16_key = key->key;
    if(ps16_key->sk) {
      pbcext_element_Fr_free(ps16_key->sk);
      ps16_key->sk = NULL;
    }
    if(ps16_key->sigma1) {
      pbcext_element_G1_free(ps16_key->sigma1);
      ps16_key->sigma1 = NULL;
    }
    if(ps16_key->sigma2) {
      pbcext_element_G1_free(ps16_key->sigma2);
      ps16_key->sigma2 = NULL;
    }
    if(ps16_key->e) {
      pbcext_element_GT_free(ps16_key->e);
      ps16_key->e = NULL;
    }
    mem_free(key->key); key->key = NULL;
    key->key = NULL;
  }
  
  mem_free(key); key = NULL;

  return IOK;

}

int ps16_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  ps16_mem_key_t *ps16_dst, *ps16_src;
  int rc;
  
  if(!dst || dst->scheme != GROUPSIG_PS16_CODE ||
     !src || src->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_mem_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  ps16_dst = dst->key;
  ps16_src = src->key;
  rc = IOK;

  /* Copy the elements */
  if(ps16_src->sk) {
    if(!(ps16_dst->sk = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, ps16_mem_key_copy);
    if(pbcext_element_Fr_set(ps16_dst->sk, ps16_src->sk) == IERROR)
      GOTOENDRC(IERROR, ps16_mem_key_copy);
  }

  if(ps16_src->sigma1) {
    if(!(ps16_dst->sigma1 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ps16_mem_key_copy); 
    if(pbcext_element_G1_set(ps16_dst->sigma1, ps16_src->sigma1) == IERROR)
      GOTOENDRC(IERROR, ps16_mem_key_copy);
  }

  if(ps16_src->sigma2) {
    if(!(ps16_dst->sigma2 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ps16_mem_key_copy);
    if(pbcext_element_G1_set(ps16_dst->sigma2, ps16_src->sigma2) == IERROR)
      GOTOENDRC(IERROR, ps16_mem_key_copy);
  }

  if(ps16_src->e) {
    if(!(ps16_dst->e = pbcext_element_GT_init()))
      GOTOENDRC(IERROR, ps16_mem_key_copy);
    if(pbcext_element_GT_set(ps16_dst->e, ps16_src->e) == IERROR)
      GOTOENDRC(IERROR, ps16_mem_key_copy);    
  }
  
 ps16_mem_key_copy_end:

  if(rc == IERROR) {
    if(ps16_dst->sk) {
      pbcext_element_Fr_free(ps16_dst->sk);
      ps16_dst->sk = NULL;
    }
    if(ps16_dst->sigma1) {
      pbcext_element_G1_free(ps16_dst->sigma1);
      ps16_dst->sigma1 = NULL;
    }
    if(ps16_dst->sigma2) {
      pbcext_element_G1_free(ps16_dst->sigma2);
      ps16_dst->sigma2 = NULL;
    }
    if(ps16_dst->e) {
      pbcext_element_GT_free(ps16_dst->e);
      ps16_dst->e = NULL;
    }
  }

  return rc;

}

int ps16_mem_key_get_size(groupsig_key_t *key) {

  ps16_mem_key_t *ps16_key;
  uint64_t size64, ssk, ssigma1, ssigma2, se;
  
  if(!key || key->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_mem_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  ssk = ssigma1 = ssigma2 = se = 0;
  ps16_key = key->key;
  
  if(ps16_key->sk) { if(pbcext_element_Fr_byte_size(&ssk) == IERROR) return -1; }
  if(ps16_key->sigma1) { if(pbcext_element_G1_byte_size(&ssigma1) == IERROR) return -1; }
  if(ps16_key->sigma2) { if(pbcext_element_G1_byte_size(&ssigma2) == IERROR) return -1; }
  if(ps16_key->e) { if(pbcext_element_GT_byte_size(&se) == IERROR) return -1; }

  size64 = sizeof(uint8_t)*2 + sizeof(int)*4+ ssk + ssigma1 + ssigma2 + se;

  if(size64 > INT_MAX) return -1;
  return (int) size64;

}

int ps16_mem_key_export(byte_t **bytes,
			uint32_t *size,
			groupsig_key_t *key) {

  ps16_mem_key_t *ps16_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;
  uint8_t code, type;  
  
  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_mem_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  ps16_key = key->key;
  
  /* Get the number of bytes to represent the key */
  if ((_size = ps16_mem_key_get_size(key)) == -1) {
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }
  
  /* Dump GROUPSIG_PS16_CODE */
  code = GROUPSIG_PS16_CODE;
  _bytes[ctr++] = code;

  /* Dump key type */
  type = GROUPSIG_KEY_MEMKEY;
  _bytes[ctr++] = GROUPSIG_KEY_MEMKEY;
  
  /* Dump sk */
  if (ps16_key->sk) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, ps16_key->sk) == IERROR) 
      GOTOENDRC(IERROR, ps16_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump sigma1 */
  if (ps16_key->sigma1) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, ps16_key->sigma1) == IERROR)
      GOTOENDRC(IERROR, ps16_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump sigma2 */
  if (ps16_key->sigma2) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, ps16_key->sigma2) == IERROR)
      GOTOENDRC(IERROR, ps16_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }
  

  /* Dump e */
  if (ps16_key->e) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_GT_bytes(&__bytes, &len, ps16_key->e) == IERROR) 
      GOTOENDRC(IERROR, ps16_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ps16_mem_key_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, ps16_mem_key_export);
  }  

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }
  
  *size = ctr;  
  
 ps16_mem_key_export_end:
  
  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }  

  return rc;
  
}

groupsig_key_t* ps16_mem_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  ps16_mem_key_t *ps16_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "ps16_mem_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;
  
  if(!(key = ps16_mem_key_init())) {
    return NULL;
  }

  ps16_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ps16_mem_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, ps16_mem_key_import);
  }

  /* Next  byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MEMKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ps16_mem_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, ps16_mem_key_import);
  }

  /* Get sk */
  if(!(ps16_key->sk = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, ps16_mem_key_import);
  if(pbcext_get_element_Fr_bytes(ps16_key->sk, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ps16_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(ps16_key->sk); ps16_key->sk = NULL;
  } else {
    ctr += len;
  }

  /* Get sigma1 */
  if(!(ps16_key->sigma1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ps16_mem_key_import);
  if(pbcext_get_element_G1_bytes(ps16_key->sigma1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ps16_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(ps16_key->sigma1); ps16_key->sigma1 = NULL;
  } else {
    ctr += len;
  }

  /* Get sigma2 */  
  if(!(ps16_key->sigma2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ps16_mem_key_import);
  if(pbcext_get_element_G1_bytes(ps16_key->sigma2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ps16_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(ps16_key->sigma2); ps16_key->sigma2 = NULL;
  } else {
    ctr += len;
  }  

  /* Get e */
  if(!(ps16_key->e = pbcext_element_GT_init()))
    GOTOENDRC(IERROR, ps16_mem_key_import);
  if(pbcext_get_element_GT_bytes(ps16_key->e, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ps16_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_GT_free(ps16_key->e); ps16_key->e = NULL;
  } else {
    ctr += len;
  }  
 

 ps16_mem_key_import_end:
  
  if(rc == IERROR && key) { ps16_mem_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  
  return NULL; 
}

char* ps16_mem_key_to_string(groupsig_key_t *key) {

  if(!key || key->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_mem_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  return NULL;

}

/* mem_key.c ends here */
