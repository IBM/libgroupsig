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

#include "dl21seq.h"
#include "groupsig/dl21seq/mem_key.h"
#include "shim/base64.h"
#include "misc/misc.h"
#include "sys/mem.h"

groupsig_key_t* dl21seq_mem_key_init() {

  groupsig_key_t *key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (dl21seq_mem_key_t *) mem_malloc(sizeof(dl21seq_mem_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_DL21SEQ_CODE;
  
  return key;

}

int dl21seq_mem_key_free(groupsig_key_t *key) {

  dl21seq_mem_key_t *dl21seq_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "dl21seq_mem_key_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_DL21SEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_mem_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    dl21seq_key = key->key;
    if(dl21seq_key->A) { pbcext_element_G1_free(dl21seq_key->A); dl21seq_key->A = NULL; }
    if(dl21seq_key->x) { pbcext_element_Fr_free(dl21seq_key->x); dl21seq_key->x = NULL; }
    if(dl21seq_key->y) { pbcext_element_Fr_free(dl21seq_key->y); dl21seq_key->y = NULL; }
    if(dl21seq_key->s) { pbcext_element_Fr_free(dl21seq_key->s); dl21seq_key->s = NULL; }
    if(dl21seq_key->H) { pbcext_element_G1_free(dl21seq_key->H); dl21seq_key->H = NULL; }
    if(dl21seq_key->h2s) {
      pbcext_element_G1_free(dl21seq_key->h2s);
      dl21seq_key->h2s = NULL;
    }
    if(dl21seq_key->k) { prf_key_free(dl21seq_key->k); dl21seq_key->k = NULL; }
    if(dl21seq_key->kk) { prf_key_free(dl21seq_key->kk); dl21seq_key->kk = NULL; }
    mem_free(key->key);
    key->key = NULL;
  }
  
  mem_free(key);
  
  return IOK;

}

int dl21seq_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  dl21seq_mem_key_t *dl21seq_dst, *dl21seq_src;
  int rc;
  
  if(!dst  || dst->scheme != GROUPSIG_DL21SEQ_CODE || 
     !src  || src->scheme != GROUPSIG_DL21SEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_mem_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  dl21seq_dst = dst->key;
  dl21seq_src = src->key;

  rc = IOK;
  
  /* Copy the elements */
  if(dl21seq_src->A) {
    if(!(dl21seq_dst->A = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, dl21seq_mem_key_copy);
    if(pbcext_element_G1_set(dl21seq_dst->A, dl21seq_src->A) == IERROR)
      GOTOENDRC(IERROR, dl21seq_mem_key_copy);
  }
  
  if(dl21seq_src->x) {  
    if(!(dl21seq_dst->x = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, dl21seq_mem_key_copy);
    if(pbcext_element_Fr_set(dl21seq_dst->x, dl21seq_src->x) == IERROR)
      GOTOENDRC(IERROR, dl21seq_mem_key_copy);
  }

  if(dl21seq_src->y) {  
    if(!(dl21seq_dst->y = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, dl21seq_mem_key_copy);
    if(pbcext_element_Fr_set(dl21seq_dst->y, dl21seq_src->y) == IERROR)
      GOTOENDRC(IERROR, dl21seq_mem_key_copy);
  }

  if(dl21seq_src->s) {  
    if(!(dl21seq_dst->s = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, dl21seq_mem_key_copy);
    if(pbcext_element_Fr_set(dl21seq_dst->s, dl21seq_src->s) == IERROR)
      GOTOENDRC(IERROR, dl21seq_mem_key_copy);
  }

  if(dl21seq_src->H) {  
    if(!(dl21seq_dst->H = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, dl21seq_mem_key_copy);
    if(pbcext_element_G1_set(dl21seq_dst->H, dl21seq_src->H) == IERROR)
      GOTOENDRC(IERROR, dl21seq_mem_key_copy);
  }

  if(dl21seq_src->h2s) {  
    if(!(dl21seq_dst->h2s = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, dl21seq_mem_key_copy);
    if(pbcext_element_G1_set(dl21seq_dst->h2s, dl21seq_src->h2s) == IERROR)
      GOTOENDRC(IERROR, dl21seq_mem_key_copy);
  }

  if(dl21seq_src->k) {
    if (!(dl21seq_dst->k = prf_key_init())) GOTOENDRC(IERROR, dl21seq_mem_key_copy);
    memcpy(dl21seq_dst->k->bytes, dl21seq_src->k->bytes, dl21seq_src->k->len);
  }

  if(dl21seq_src->kk) {
    if (!(dl21seq_dst->kk = prf_key_init())) GOTOENDRC(IERROR, dl21seq_mem_key_copy);
    memcpy(dl21seq_dst->kk->bytes, dl21seq_src->kk->bytes, dl21seq_src->kk->len);
  }  
  
 dl21seq_mem_key_copy_end:
  
  if (rc == IERROR) {
    if(dl21seq_dst->A) { pbcext_element_G1_free(dl21seq_dst->A); dl21seq_dst->A = NULL; }
    if(dl21seq_dst->x) { pbcext_element_Fr_free(dl21seq_dst->x); dl21seq_dst->x = NULL; }
    if(dl21seq_dst->y) { pbcext_element_Fr_free(dl21seq_dst->y); dl21seq_dst->y = NULL; }
    if(dl21seq_dst->s) { pbcext_element_Fr_free(dl21seq_dst->s); dl21seq_dst->s = NULL; }
    if(dl21seq_dst->H) { pbcext_element_G1_free(dl21seq_dst->H); dl21seq_dst->H = NULL; }
    if(dl21seq_dst->h2s) {
      pbcext_element_G1_free(dl21seq_dst->h2s);
      dl21seq_dst->h2s = NULL;
    }
    if(dl21seq_dst->k) { prf_key_free(dl21seq_dst->k); dl21seq_dst->k = NULL; }
    if(dl21seq_dst->kk) { prf_key_free(dl21seq_dst->kk); dl21seq_dst->kk = NULL; }
  }
  
  return rc;

}

int dl21seq_mem_key_get_size(groupsig_key_t *key) {

  dl21seq_mem_key_t *dl21seq_key;
  int size;
  uint64_t sA, sx, sy, ss, sd, sH, sh2s, sk, skk;
  
  if(!key || key->scheme != GROUPSIG_DL21SEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_mem_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  dl21seq_key = key->key;

  sA = sx = sy = ss = sd = sH = sh2s = sk = skk = 0;

  if(dl21seq_key->A) { if(pbcext_element_G1_byte_size(&sA) == -1) return -1; }
  if(dl21seq_key->x) { if(pbcext_element_Fr_byte_size(&sx) == -1) return -1; }
  if(dl21seq_key->y) { if(pbcext_element_Fr_byte_size(&sy) == -1) return -1; }
  if(dl21seq_key->s) { if(pbcext_element_Fr_byte_size(&ss) == -1) return -1; }
  if(dl21seq_key->H) { if(pbcext_element_G1_byte_size(&sH) == -1) return -1; }
  if(dl21seq_key->h2s) { if(pbcext_element_G1_byte_size(&sh2s) == -1) return -1; }
  if(dl21seq_key->k) sk = dl21seq_key->k->len;
  if(dl21seq_key->kk) skk = dl21seq_key->kk->len;  

  if ((int) sA + sx + sy + ss + sH + sh2s + sk + skk +
      sizeof(int)*6+4 > INT_MAX) return -1;
  size = (int) sA + sx + sy + ss + sH + sh2s + sk+ skk + sizeof(int)*6+4;

  return size;
  
}

int dl21seq_mem_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key) {

  dl21seq_mem_key_t *dl21seq_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  uint32_t _size;
  int ctr, rc;
  
  if(!key || key->scheme != GROUPSIG_DL21SEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_mem_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  dl21seq_key = key->key;

  if ((_size = dl21seq_mem_key_get_size(key)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }

  /* Dump GROUPSIG_DL21SEQ_CODE */
  _bytes[ctr++] = GROUPSIG_DL21SEQ_CODE;

  /* Dump key type */
  _bytes[ctr++] = GROUPSIG_KEY_MEMKEY;

  /* Dump A */
  if (dl21seq_key->A) {
    __bytes = &_bytes[ctr];    
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, dl21seq_key->A) == IERROR)
      GOTOENDRC(IERROR, dl21seq_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump x */
  if (dl21seq_key->x) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, dl21seq_key->x) == IERROR)
      GOTOENDRC(IERROR, dl21seq_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump y */
  if (dl21seq_key->y) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, dl21seq_key->y) == IERROR)
      GOTOENDRC(IERROR, dl21seq_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }    

  /* Dump s */
  if (dl21seq_key->s) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, dl21seq_key->s) == IERROR)
      GOTOENDRC(IERROR, dl21seq_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump H */
  if (dl21seq_key->H) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, dl21seq_key->H) == IERROR)
      GOTOENDRC(IERROR, dl21seq_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); } 

  /* Dump h2s */
  if (dl21seq_key->h2s) {
    __bytes = &_bytes[ctr];    
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, dl21seq_key->h2s) == IERROR)
      GOTOENDRC(IERROR, dl21seq_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump k */
  if (dl21seq_key->k && dl21seq_key->k->bytes && dl21seq_key->k->len) {
    _bytes[ctr] = dl21seq_key->k->len;
    ctr++;
    memcpy(&_bytes[ctr], dl21seq_key->k->bytes, dl21seq_key->k->len);
    ctr += dl21seq_key->k->len;
  } else {
    ctr += sizeof(uint8_t);
  }
  
  /* Dump kk */
  if (dl21seq_key->kk && dl21seq_key->kk->bytes && dl21seq_key->kk->len) {
    _bytes[ctr] = dl21seq_key->k->len;
    ctr++;    
    memcpy(&_bytes[ctr], dl21seq_key->kk->bytes, dl21seq_key->kk->len);
    ctr += dl21seq_key->kk->len;  
  } else {
    ctr += sizeof(uint8_t);
  }
    
  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "dl21seq_mem_key_export", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, dl21seq_mem_key_export);
  }  

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }
  
  *size = ctr;
  
 dl21seq_mem_key_export_end:
  
  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  
  return rc;    
  
}

groupsig_key_t* dl21seq_mem_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  dl21seq_mem_key_t *dl21seq_key;
  uint64_t len;
  int rc, ctr;
  uint8_t type, scheme;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_mem_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  if(!(key = dl21seq_mem_key_init())) {
    return NULL;
  }

  rc = IOK;
  ctr = 0;
  dl21seq_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "dl21seq_mem_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, dl21seq_mem_key_import);
  } 
  
  /* Next byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MEMKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "dl21seq_mem_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, dl21seq_mem_key_import);
  }    

  /* Get A */
  if(!(dl21seq_key->A = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21seq_mem_key_import);
  if(pbcext_get_element_G1_bytes(dl21seq_key->A, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21seq_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(dl21seq_key->A); dl21seq_key->A = NULL;
  } else {
    ctr += len;
  }

  /* Get x */
  if(!(dl21seq_key->x = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, dl21seq_mem_key_import);
  if(pbcext_get_element_Fr_bytes(dl21seq_key->x, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21seq_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(dl21seq_key->x); dl21seq_key->x = NULL;
  } else {
    ctr += len;
  }

  /* Get y */
  if(!(dl21seq_key->y = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, dl21seq_mem_key_import);
  if(pbcext_get_element_Fr_bytes(dl21seq_key->y, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21seq_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(dl21seq_key->y); dl21seq_key->y = NULL;
  } else {
    ctr += len;
  }

  /* Get s */
  if(!(dl21seq_key->s = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, dl21seq_mem_key_import);
  if(pbcext_get_element_Fr_bytes(dl21seq_key->s, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21seq_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(dl21seq_key->s); dl21seq_key->s = NULL;
  } else {
    ctr += len;
  }

  /* Get H */
  if(!(dl21seq_key->H = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21seq_mem_key_import);
  if(pbcext_get_element_G1_bytes(dl21seq_key->H, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21seq_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(dl21seq_key->H); dl21seq_key->H = NULL;
  } else {
    ctr += len;
  }

  /* Get h2s */
  if(!(dl21seq_key->h2s = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21seq_mem_key_import);
  if(pbcext_get_element_G1_bytes(dl21seq_key->h2s, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21seq_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(dl21seq_key->h2s); dl21seq_key->h2s = NULL;
  } else {
    ctr += len;
  }

  /* k */
  if(!(dl21seq_key->k = prf_key_init()))
    GOTOENDRC(IERROR, dl21seq_mem_key_import);
  // Currently, we only support BLAKE2 lengths in PRF. This may change.
  if (source[ctr] && source[ctr] != dl21seq_key->k->len)
    GOTOENDRC(IERROR, dl21seq_mem_key_import);
  ctr++;

  if (source[ctr-1]) {
    memcpy(dl21seq_key->k->bytes, &source[ctr], dl21seq_key->k->len);
    ctr += dl21seq_key->k->len;
  }

  /* kk */
  if(!(dl21seq_key->kk = prf_key_init()))
    GOTOENDRC(IERROR, dl21seq_mem_key_import);
  // Currently, we only support BLAKE2 lengths in PRF. This may change.
  if (source[ctr] && source[ctr] != dl21seq_key->kk->len)
    GOTOENDRC(IERROR, dl21seq_mem_key_import);
  ctr++;

  if (source[ctr-1]) {
    memcpy(dl21seq_key->kk->bytes, &source[ctr], dl21seq_key->kk->len);
    ctr += dl21seq_key->kk->len;
  }
  
 dl21seq_mem_key_import_end:

  if(rc == IERROR && key) { dl21seq_mem_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  return NULL;  
  
}

char* dl21seq_mem_key_to_string(groupsig_key_t *key) {

  if(!key || key->scheme != GROUPSIG_DL21SEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_mem_key_to_string",
	       __LINE__, LOGERROR);
    return NULL;
  }

  return NULL;

}

/* mem_key.c ends here */
