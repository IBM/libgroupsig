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

#include "gl19.h"
#include "logger.h"
#include "groupsig/gl19/mem_key.h"
#include "shim/base64.h"
#include "misc/misc.h"
#include "sys/mem.h"

groupsig_key_t* gl19_mem_key_init() {

  groupsig_key_t *key;
  gl19_mem_key_t *gl19_key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (gl19_mem_key_t *) mem_malloc(sizeof(gl19_mem_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  /* Initialize internal fields */
  gl19_key = key->key;
  gl19_key->A = NULL;
  gl19_key->x = NULL;
  gl19_key->y = NULL;
  gl19_key->s = NULL;
  gl19_key->l = 0;
  gl19_key->d = NULL;  
  gl19_key->H = NULL;
  gl19_key->h2s = NULL;
  gl19_key->h3d = NULL;    

  key->scheme = GROUPSIG_GL19_CODE;
  
  return key;

}

int gl19_mem_key_free(groupsig_key_t *key) {

  gl19_mem_key_t *gl19_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gl19_mem_key_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_mem_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    gl19_key = key->key;
    if(gl19_key->A) { pbcext_element_G1_free(gl19_key->A); gl19_key->A = NULL; }
    if(gl19_key->x) { pbcext_element_Fr_free(gl19_key->x); gl19_key->x = NULL; }
    if(gl19_key->y) { pbcext_element_Fr_free(gl19_key->y); gl19_key->y = NULL; }
    if(gl19_key->s) { pbcext_element_Fr_free(gl19_key->s); gl19_key->s = NULL; }
    if(gl19_key->d) { pbcext_element_Fr_free(gl19_key->d); gl19_key->d = NULL; }
    if(gl19_key->H) { pbcext_element_G1_free(gl19_key->H); gl19_key->H = NULL; }
    if(gl19_key->h2s) {
      pbcext_element_G1_free(gl19_key->h2s);
      gl19_key->h2s = NULL;
    }
    if(gl19_key->h3d) {
      pbcext_element_G1_free(gl19_key->h3d);
      gl19_key->h3d = NULL;
    }    
    mem_free(key->key);
    key->key = NULL;
  }
  
  mem_free(key);
  
  return IOK;

}

int gl19_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  gl19_mem_key_t *gl19_dst, *gl19_src;
  int rc;
  
  if(!dst  || dst->scheme != GROUPSIG_GL19_CODE || 
     !src  || src->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_mem_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  gl19_dst = dst->key;
  gl19_src = src->key;

  rc = IOK;
  
  /* Copy the elements */
  if(gl19_src->A) {
    if(!(gl19_dst->A = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, gl19_mem_key_copy);
    if(pbcext_element_G1_set(gl19_dst->A, gl19_src->A) == IERROR)
      GOTOENDRC(IERROR, gl19_mem_key_copy);
  }

  if(gl19_src->x) {
    if(!(gl19_dst->x = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, gl19_mem_key_copy);
    if(pbcext_element_Fr_set(gl19_dst->x, gl19_src->x) == IERROR)
      GOTOENDRC(IERROR, gl19_mem_key_copy);
  }

  if(gl19_src->y) {
    if(!(gl19_dst->y = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, gl19_mem_key_copy);
    if(pbcext_element_Fr_set(gl19_dst->y, gl19_src->y) == IERROR)
      GOTOENDRC(IERROR, gl19_mem_key_copy);
  }

  if(gl19_src->s) {
    if(!(gl19_dst->s = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, gl19_mem_key_copy);
    if(pbcext_element_Fr_set(gl19_dst->s, gl19_src->s) == IERROR)
      GOTOENDRC(IERROR, gl19_mem_key_copy);
  }

  gl19_dst->l = gl19_src->l;

  if(gl19_src->d) {
    if(!(gl19_dst->d = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, gl19_mem_key_copy);
    if(pbcext_element_Fr_set(gl19_dst->s, gl19_src->d) == IERROR)
      GOTOENDRC(IERROR, gl19_mem_key_copy);
  }  

  if(gl19_src->H) {
    if(!(gl19_dst->H = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, gl19_mem_key_copy);
    if(pbcext_element_G1_set(gl19_dst->H, gl19_src->H) == IERROR)
      GOTOENDRC(IERROR, gl19_mem_key_copy);
  }

  if(gl19_src->h2s) {
    if(!(gl19_dst->h2s = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, gl19_mem_key_copy);
    if(pbcext_element_G1_set(gl19_dst->h2s, gl19_src->h2s) == IERROR)
      GOTOENDRC(IERROR, gl19_mem_key_copy);
  }

  if(gl19_src->h3d) {
    if(!(gl19_dst->h3d = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, gl19_mem_key_copy);
    if(pbcext_element_G1_set(gl19_dst->h3d, gl19_src->h3d) == IERROR)
      GOTOENDRC(IERROR, gl19_mem_key_copy);
  }
    
 gl19_mem_key_copy_end:
  
  if (rc == IERROR) {
    if(gl19_dst->A) { pbcext_element_G1_free(gl19_dst->A); gl19_dst->A = NULL; }
    if(gl19_dst->x) { pbcext_element_Fr_free(gl19_dst->x); gl19_dst->x = NULL; }
    if(gl19_dst->y) { pbcext_element_Fr_free(gl19_dst->y); gl19_dst->y = NULL; }
    if(gl19_dst->s) { pbcext_element_Fr_free(gl19_dst->s); gl19_dst->s = NULL; }
    if(gl19_dst->d) { pbcext_element_Fr_free(gl19_dst->d); gl19_dst->d = NULL; }
    if(gl19_dst->H) { pbcext_element_G1_free(gl19_dst->H); gl19_dst->H = NULL; }
    if(gl19_dst->h2s) {
      pbcext_element_G1_free(gl19_dst->h2s);
      gl19_dst->h2s = NULL;
    }
    if(gl19_dst->h3d) {
      pbcext_element_G1_free(gl19_dst->h3d);
      gl19_dst->h3d = NULL;
    }    
  }
  
  return rc;

}

int gl19_mem_key_get_size(groupsig_key_t *key) {

  gl19_mem_key_t *gl19_key;
  int size;
  uint64_t sA, sx, sy, ss, sd, sH, sh2s, sh3d;
  
  if(!key || key->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_mem_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  gl19_key = key->key;

  sA = sx = sy = ss = sd = sH = sh2s = sh3d = 0;
  
  if(gl19_key->A) { if(pbcext_element_G1_byte_size(&sA) == -1) return -1; }
  if(gl19_key->x) { if(pbcext_element_Fr_byte_size(&sx) == -1) return -1; }
  if(gl19_key->y) { if(pbcext_element_Fr_byte_size(&sy) == -1) return -1; }
  if(gl19_key->s) { if(pbcext_element_Fr_byte_size(&ss) == -1) return -1; }
  if(gl19_key->d) { if(pbcext_element_Fr_byte_size(&sd) == -1) return -1; }  
  if(gl19_key->H) { if(pbcext_element_G1_byte_size(&sH) == -1) return -1; }
  if(gl19_key->h2s) { if(pbcext_element_G1_byte_size(&sh2s) == -1) return -1; }
  if(gl19_key->h3d) { if(pbcext_element_G1_byte_size(&sh3d) == -1) return -1; }

  if (sA + sx + sy + ss + sizeof(uint64_t) + sd + sH + sh2s + sh3d +
      sizeof(int)*8+2 > INT_MAX) return -1;
  size = (int) sA + sx + sy + ss + sizeof(uint64_t) +
    sd + sH + sh2s + sh3d + sizeof(int)*8+2;
  
  return size;  

}

int gl19_mem_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key) {

  gl19_mem_key_t *gl19_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  uint32_t _size;
  int ctr, rc;
  
  if(!key || key->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_mem_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  gl19_key = key->key;

  if ((_size = gl19_mem_key_get_size(key)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }
  
  /* Dump GROUPSIG_GL19_CODE */
  _bytes[ctr++] = GROUPSIG_GL19_CODE;
  
  /* Dump key type */
  _bytes[ctr++] = GROUPSIG_KEY_MEMKEY;
  
  /* Dump A */
  if (gl19_key->A) {
    __bytes = &_bytes[ctr];    
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_key->A) == IERROR)
      GOTOENDRC(IERROR, gl19_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump x */
  if (gl19_key->x) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, gl19_key->x) == IERROR)
      GOTOENDRC(IERROR, gl19_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump y */
  if (gl19_key->y) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, gl19_key->y) == IERROR)
      GOTOENDRC(IERROR, gl19_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }    

  /* Dump s */
  if (gl19_key->s) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, gl19_key->s) == IERROR)
      GOTOENDRC(IERROR, gl19_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump l */
  memcpy(&_bytes[ctr], &gl19_key->l, sizeof(uint64_t));
  ctr += sizeof(uint64_t);

  /* Dump d */
  if (gl19_key->d) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, gl19_key->d) == IERROR)
      GOTOENDRC(IERROR, gl19_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }  

  /* Dump H */
  if (gl19_key->H) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_key->H) == IERROR)
      GOTOENDRC(IERROR, gl19_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); } 

  /* Dump h2s */
  if (gl19_key->h2s) {
    __bytes = &_bytes[ctr];    
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_key->h2s) == IERROR)
      GOTOENDRC(IERROR, gl19_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump h3d */
  if (gl19_key->h3d) {
    __bytes = &_bytes[ctr];    
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_key->h3d) == IERROR)
      GOTOENDRC(IERROR, gl19_mem_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }  

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "gl19_mem_key_export", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, gl19_mem_key_export);
  }  

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  *size = ctr;

 gl19_mem_key_export_end:
  
  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  
  return rc;
  
}

groupsig_key_t* gl19_mem_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  gl19_mem_key_t *gl19_key;
  uint64_t len;
  int rc, ctr;
  uint8_t type, scheme;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "gl19_mem_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  if(!(key = gl19_mem_key_init())) {
    return NULL;
  }

  rc = IOK;
  ctr = 0;
  gl19_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "gl19_mem_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, gl19_mem_key_import);
  } 
  
  /* Next byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_MEMKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "gl19_mem_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, gl19_mem_key_import);
  }    

  /* Get A */
  if(!(gl19_key->A = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_mem_key_import);
  if(pbcext_get_element_G1_bytes(gl19_key->A, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(gl19_key->A); gl19_key->A = NULL;
  } else {
    ctr += len;
  }

  /* Get x */
  if(!(gl19_key->x = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, gl19_mem_key_import);
  if(pbcext_get_element_Fr_bytes(gl19_key->x, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(gl19_key->x); gl19_key->x = NULL;
  } else {
    ctr += len;
  }

  /* Get y */
  if(!(gl19_key->y = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, gl19_mem_key_import);
  if(pbcext_get_element_Fr_bytes(gl19_key->y, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(gl19_key->y); gl19_key->y = NULL;
  } else {
    ctr += len;
  }

  /* Get s */
  if(!(gl19_key->s = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, gl19_mem_key_import);
  if(pbcext_get_element_Fr_bytes(gl19_key->s, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(gl19_key->s); gl19_key->s = NULL;
  } else {
    ctr += len;
  }

  /* Get l */
  memcpy(&gl19_key->l, &source[ctr], sizeof(uint64_t));
  ctr += sizeof(uint64_t);

  /* Get d */
  if(!(gl19_key->d = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, gl19_mem_key_import);
  if(pbcext_get_element_Fr_bytes(gl19_key->d, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_Fr_free(gl19_key->d); gl19_key->d = NULL;
  } else {
    ctr += len;
  }  

  /* Get H */
  if(!(gl19_key->H = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_mem_key_import);
  if(pbcext_get_element_G1_bytes(gl19_key->H, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(gl19_key->H); gl19_key->H = NULL;
  } else {
    ctr += len;
  }

  /* Get h2s */
  if(!(gl19_key->h2s = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_mem_key_import);
  if(pbcext_get_element_G1_bytes(gl19_key->h2s, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(gl19_key->h2s); gl19_key->h2s = NULL;
  } else {
    ctr += len;
  }

  /* Get h3d */
  if(!(gl19_key->h3d = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_mem_key_import);
  if(pbcext_get_element_G1_bytes(gl19_key->h3d, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_mem_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(gl19_key->h3d); gl19_key->h3d = NULL;
  } else {
    ctr += len;
  }  
  
 gl19_mem_key_import_end:

  if(rc == IERROR && key) { gl19_mem_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  return NULL;

}

char* gl19_mem_key_to_string(groupsig_key_t *key) {

  if(!key || key->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_mem_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  return NULL;

}

/* mem_key.c ends here */
