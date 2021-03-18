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

#include "sysenv.h"
#include "gl19.h"
#include "logger.h"
#include "shim/base64.h"
#include "sys/mem.h"
#include "misc/misc.h"
#include "groupsig/gl19/grp_key.h"

groupsig_key_t* gl19_grp_key_init() {

  groupsig_key_t *key;
  gl19_grp_key_t *gl19_key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (gl19_grp_key_t *) mem_malloc(sizeof(gl19_grp_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_GL19_CODE;
  gl19_key = key->key;
  gl19_key->g1 = NULL;
  gl19_key->g2 = NULL;
  gl19_key->g = NULL;
  gl19_key->h = NULL;
  gl19_key->h1 = NULL;
  gl19_key->h2 = NULL;
  gl19_key->h3 = NULL;  
  gl19_key->ipk = NULL;
  gl19_key->cpk = NULL;
  gl19_key->epk = NULL;

  return key;
  
}

int gl19_grp_key_free(groupsig_key_t *key) {

  gl19_grp_key_t *gl19_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gl19_grp_key_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if(key->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_grp_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {

    gl19_key = key->key;
    if(gl19_key->g1) { pbcext_element_G1_free(gl19_key->g1); gl19_key->g1 = NULL; }
    if(gl19_key->g2) { pbcext_element_G2_free(gl19_key->g2); gl19_key->g2 = NULL; }
    if(gl19_key->g) { pbcext_element_G1_free(gl19_key->g); gl19_key->g = NULL; }
    if(gl19_key->h) { pbcext_element_G1_free(gl19_key->h); gl19_key->h = NULL; }
    if(gl19_key->h1) { pbcext_element_G1_free(gl19_key->h1); gl19_key->h1 = NULL; }
    if(gl19_key->h2) { pbcext_element_G1_free(gl19_key->h2); gl19_key->h2 = NULL; }
    if(gl19_key->h3) { pbcext_element_G1_free(gl19_key->h3); gl19_key->h3 = NULL; }
    if(gl19_key->ipk) { pbcext_element_G2_free(gl19_key->ipk); gl19_key->ipk = NULL; }
    if(gl19_key->cpk) { pbcext_element_G1_free(gl19_key->cpk); gl19_key->cpk = NULL; }
    if(gl19_key->epk) { pbcext_element_G1_free(gl19_key->epk); gl19_key->epk = NULL; }
    mem_free(key->key); key->key = NULL;
  }

  mem_free(key);  

  return IOK;

}

int gl19_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  gl19_grp_key_t *gl19_dst, *gl19_src;
  int rc;
  
  if(!dst || dst->scheme != GROUPSIG_GL19_CODE ||
     !src || src->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_grp_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  gl19_dst = dst->key;
  gl19_src = src->key;

  /* Copy the elements */
  if(gl19_dst->g1) {
    if(!(gl19_dst->g1 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, gl19_grp_key_copy);
    if(pbcext_element_G1_set(gl19_dst->g1, gl19_src->g1) == IERROR)
      GOTOENDRC(IERROR, gl19_grp_key_copy);
  }

  if(gl19_dst->g2) {
    if(!(gl19_dst->g2 = pbcext_element_G2_init()))
      GOTOENDRC(IERROR, gl19_grp_key_copy);
    if(pbcext_element_G2_set(gl19_dst->g2, gl19_src->g2) == IERROR)
      GOTOENDRC(IERROR, gl19_grp_key_copy);
  }

  if(gl19_dst->g) {
    if(!(gl19_dst->g = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, gl19_grp_key_copy);
    if(pbcext_element_G1_set(gl19_dst->g, gl19_src->g) == IERROR)
      GOTOENDRC(IERROR, gl19_grp_key_copy);
  }

  if(gl19_dst->h) {
    if(!(gl19_dst->h = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, gl19_grp_key_copy);
    if(pbcext_element_G1_set(gl19_dst->h, gl19_src->h) == IERROR)
      GOTOENDRC(IERROR, gl19_grp_key_copy);
  }

  if(gl19_dst->h1) {
    if(!(gl19_dst->h1 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, gl19_grp_key_copy);
    if(pbcext_element_G1_set(gl19_dst->h1, gl19_src->h1) == IERROR)
      GOTOENDRC(IERROR, gl19_grp_key_copy);
  }

  if(gl19_dst->h2) {
    if(!(gl19_dst->h2 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, gl19_grp_key_copy);
    if(pbcext_element_G1_set(gl19_dst->h2, gl19_src->h2) == IERROR)
      GOTOENDRC(IERROR, gl19_grp_key_copy);
  }

  if(gl19_dst->h3) {
    if(!(gl19_dst->h3 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, gl19_grp_key_copy);
    if(pbcext_element_G1_set(gl19_dst->h3, gl19_src->h3) == IERROR)
      GOTOENDRC(IERROR, gl19_grp_key_copy);
  }  

  if(gl19_dst->ipk) {
    if(!(gl19_dst->ipk = pbcext_element_G2_init()))
      GOTOENDRC(IERROR, gl19_grp_key_copy);
    if(pbcext_element_G2_set(gl19_dst->ipk, gl19_src->ipk) == IERROR)
      GOTOENDRC(IERROR, gl19_grp_key_copy);
  }

  if(gl19_dst->cpk) {
    if(!(gl19_dst->cpk = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, gl19_grp_key_copy);
    if(pbcext_element_G1_set(gl19_dst->cpk, gl19_src->cpk) == IERROR)
      GOTOENDRC(IERROR, gl19_grp_key_copy);
  }

  if(gl19_dst->epk) {
    if(!(gl19_dst->epk = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, gl19_grp_key_copy);
    if(pbcext_element_G1_set(gl19_dst->epk, gl19_src->epk) == IERROR)
      GOTOENDRC(IERROR, gl19_grp_key_copy);
  }  
  
 gl19_grp_key_copy_end:

  if (rc == IERROR) {
    if(gl19_dst->g1) { pbcext_element_G1_free(gl19_dst->g1); gl19_dst->g1 = NULL; }
    if(gl19_dst->g2) { pbcext_element_G2_free(gl19_dst->g2); gl19_dst->g2 = NULL; }
    if(gl19_dst->g) { pbcext_element_G1_free(gl19_dst->g); gl19_dst->g = NULL; }
    if(gl19_dst->h) { pbcext_element_G1_free(gl19_dst->h); gl19_dst->h = NULL; }
    if(gl19_dst->h1) { pbcext_element_G1_free(gl19_dst->h1); gl19_dst->h1 = NULL; }
    if(gl19_dst->h2) { pbcext_element_G1_free(gl19_dst->h2); gl19_dst->h2 = NULL; }
    if(gl19_dst->h3) { pbcext_element_G1_free(gl19_dst->h3); gl19_dst->h3 = NULL; }
    if(gl19_dst->ipk) { pbcext_element_G2_free(gl19_dst->ipk); gl19_dst->ipk = NULL; }
    if(gl19_dst->cpk) { pbcext_element_G1_free(gl19_dst->cpk); gl19_dst->cpk = NULL; }
    if(gl19_dst->epk) { pbcext_element_G1_free(gl19_dst->epk); gl19_dst->epk = NULL; }
  }
  
  return rc;

}

int gl19_grp_key_get_size(groupsig_key_t *key) {

  gl19_grp_key_t *gl19_key;
  int size;
  uint64_t sg1, sg2, sg, sh, sh1, sh2, sh3, sipk, scpk, sepk;
  
  if(!key || key->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_grp_key_get_size_in_format",
	       __LINE__, LOGERROR);
    return -1;
  }
  
  gl19_key = key->key;
  sg1 = sg2 = sg = sh = sh1 = sh2 = sh3 = sipk = scpk = sepk = 0;

  if(gl19_key->g1) { if(pbcext_element_G1_byte_size(&sg1) == IERROR) return -1; }
  if(gl19_key->g2) { if(pbcext_element_G2_byte_size(&sg2) == IERROR) return -1; }
  if(gl19_key->g) { if(pbcext_element_G1_byte_size(&sg) == IERROR) return -1; }
  if(gl19_key->h) { if(pbcext_element_G1_byte_size(&sh) == IERROR) return -1; }
  if(gl19_key->h1) { if(pbcext_element_G1_byte_size(&sh1) == IERROR) return -1; }
  if(gl19_key->h2) { if(pbcext_element_G1_byte_size(&sh2) == IERROR) return -1; }
  if(gl19_key->h3) { if(pbcext_element_G1_byte_size(&sh3) == IERROR) return -1; }
  if(gl19_key->ipk) { if(pbcext_element_G2_byte_size(&sipk) == IERROR) return -1; }
  if(gl19_key->cpk) { if(pbcext_element_G1_byte_size(&scpk) == IERROR) return -1; }
  if(gl19_key->epk) { if(pbcext_element_G1_byte_size(&sepk) == IERROR) return -1; }

  if(sg1 + sg2 + sg + sh + sh1 + sh2 + sh3 + sipk + scpk + sepk + sizeof(int)*9+2 > INT_MAX)
    return -1;
  size = (int) sg1 + sg2 + sg + sh + sh1 + sh2 + sh3 + sipk + scpk + sepk + sizeof(int)*10+2;
  
  return size;
  
}

int gl19_grp_key_export(byte_t **bytes,
			uint32_t *size,
			groupsig_key_t *key) {

  gl19_grp_key_t *gl19_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;
  
  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_grp_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  gl19_key = key->key;
  
  /* Get the number of bytes to represent the key */
  if ((_size = gl19_grp_key_get_size(key)) == -1) {
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }
  
  /* Dump GROUPSIG_GL19_CODE */
  _bytes[ctr++] = GROUPSIG_GL19_CODE;

  /* Dump key type */
  _bytes[ctr++] = GROUPSIG_KEY_GRPKEY;

  /* Dump g1 */
  if(gl19_key->g1) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_key->g1) == IERROR)
      GOTOENDRC(IERROR, gl19_grp_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump g2 */
  if(gl19_key->g2) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G2_bytes(&__bytes, &len, gl19_key->g2) == IERROR)
      GOTOENDRC(IERROR, gl19_grp_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump g */
  if(gl19_key->g) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_key->g) == IERROR)
      GOTOENDRC(IERROR, gl19_grp_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump h */
  if(gl19_key->h) {
    __bytes = &_bytes[ctr];    
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_key->h) == IERROR)
      GOTOENDRC(IERROR, gl19_grp_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump h1 */
  if(gl19_key->h1) {
    __bytes = &_bytes[ctr];    
   if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_key->h1) == IERROR)
     GOTOENDRC(IERROR, gl19_grp_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump h2 */
  if(gl19_key->h2) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_key->h2) == IERROR)
      GOTOENDRC(IERROR, gl19_grp_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump h3 */
  if(gl19_key->h3) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_key->h3) == IERROR)
      GOTOENDRC(IERROR, gl19_grp_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }  

  /* Dump ipk */
  if(gl19_key->ipk) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G2_bytes(&__bytes, &len, gl19_key->ipk) == IERROR)
      GOTOENDRC(IERROR, gl19_grp_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump cpk */
  if(gl19_key->cpk) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_key->cpk) == IERROR)
      GOTOENDRC(IERROR, gl19_grp_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump epk */
  if(gl19_key->epk) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_key->epk) == IERROR)
      GOTOENDRC(IERROR, gl19_grp_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "gl19_grp_key_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, gl19_grp_key_export);
  }

  *size = ctr;

 gl19_grp_key_export_end:

  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }

  return rc;
  
}

groupsig_key_t* gl19_grp_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  gl19_grp_key_t *gl19_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "gl19_grp_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;
  
  if(!(key = gl19_grp_key_init())) {
    return NULL;
  }

  gl19_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "gl19_grp_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, gl19_grp_key_import);
  }

  /* Next  byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_GRPKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "gl19_grp_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, gl19_grp_key_import);
  }

  /* Get g1 */
  if(!(gl19_key->g1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_grp_key_import);
  if(pbcext_get_element_G1_bytes(gl19_key->g1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_grp_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(gl19_key->g1); gl19_key->g1 = NULL;
  } else {
    ctr += len;
  }

  /* Get g2 */
  if(!(gl19_key->g2 = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, gl19_grp_key_import);
  if(pbcext_get_element_G2_bytes(gl19_key->g2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_grp_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G2_free(gl19_key->g2); gl19_key->g2 = NULL;
  } else {
    ctr += len;
  }

  /* Get g */
  if(!(gl19_key->g = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_grp_key_import);
  if(pbcext_get_element_G1_bytes(gl19_key->g, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_grp_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(gl19_key->g); gl19_key->g = NULL;
  } else {
    ctr += len;
  }

  /* Get h */
  if(!(gl19_key->h = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_grp_key_import);
  if(pbcext_get_element_G1_bytes(gl19_key->h, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_grp_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(gl19_key->h); gl19_key->h = NULL;
  } else {
    ctr += len;
  }

  /* Get h1 */
  if(!(gl19_key->h1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_grp_key_import);
  if(pbcext_get_element_G1_bytes(gl19_key->h1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_grp_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(gl19_key->h1); gl19_key->h1 = NULL;
  } else {
    ctr += len;
  }

  /* Get h2 */
  if(!(gl19_key->h2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_grp_key_import);
  if(pbcext_get_element_G1_bytes(gl19_key->h2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_grp_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(gl19_key->h2); gl19_key->h2 = NULL;
  } else {
    ctr += len;
  }

  /* Get h3 */
  if(!(gl19_key->h3 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_grp_key_import);
  if(pbcext_get_element_G1_bytes(gl19_key->h3, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_grp_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(gl19_key->h3); gl19_key->h3 = NULL;
  } else {
    ctr += len;
  }  

  /* Get ipk */
  if(!(gl19_key->ipk = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, gl19_grp_key_import);
  if(pbcext_get_element_G2_bytes(gl19_key->ipk, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_grp_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G2_free(gl19_key->ipk); gl19_key->ipk = NULL;
  } else {
    ctr += len;
  }

  /* Get cpk */
  if(!(gl19_key->cpk = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_grp_key_import);
  if(pbcext_get_element_G1_bytes(gl19_key->cpk, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_grp_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(gl19_key->cpk); gl19_key->cpk = NULL;
  } else {
    ctr += len;
  }

  /* Get epk */
  if(!(gl19_key->epk = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_grp_key_import);
  if(pbcext_get_element_G1_bytes(gl19_key->epk, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_grp_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(gl19_key->epk); gl19_key->epk = NULL;
  } else {
    ctr += len;
  }

 gl19_grp_key_import_end:
  
  if(rc == IERROR && key) { gl19_grp_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  return NULL;  

}

char* gl19_grp_key_to_string(groupsig_key_t *key) {

  /* return skey; */
  fprintf(stderr, "@TODO gl19_grp_key_to_string not implemented.\n");
  return NULL;

}

/* grp_key.c ends here */
