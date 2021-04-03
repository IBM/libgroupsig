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
#include "sys/mem.h"
#include "misc/misc.h"
#include "shim/base64.h"

#include "dl21.h"
#include "groupsig/dl21/grp_key.h"

groupsig_key_t* dl21_grp_key_init() {

  groupsig_key_t *key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (dl21_grp_key_t *) mem_malloc(sizeof(dl21_grp_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_DL21_CODE;

  return key;
  
}

int dl21_grp_key_free(groupsig_key_t *key) {

  dl21_grp_key_t *dl21_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "dl21_grp_key_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if(key->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_grp_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {

    dl21_key = key->key;
    pbcext_element_G1_free(dl21_key->g1); dl21_key->g1 = NULL;
    pbcext_element_G2_free(dl21_key->g2); dl21_key->g2 = NULL;
    pbcext_element_G1_free(dl21_key->h1); dl21_key->h1 = NULL;
    pbcext_element_G1_free(dl21_key->h2); dl21_key->h2 = NULL;
    pbcext_element_G2_free(dl21_key->ipk); dl21_key->ipk = NULL;
    mem_free(key->key);
    key->key = NULL;
  }

  mem_free(key);  

  return IOK;

}

int dl21_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  dl21_grp_key_t *dl21_dst, *dl21_src;
  int rc;
  
  if(!dst || dst->scheme != GROUPSIG_DL21_CODE ||
     !src || src->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_grp_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  dl21_dst = dst->key;
  dl21_src = src->key;

  /* Copy the elements */
  if(dl21_src->g1) {
    if(!(dl21_dst->g1 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, dl21_grp_key_copy);
    if(pbcext_element_G1_set(dl21_dst->g1, dl21_src->g1) == IERROR)
      GOTOENDRC(IERROR, dl21_grp_key_copy);
  }

  if(dl21_src->g2) {  
    if(!(dl21_dst->g2 = pbcext_element_G2_init()))
      GOTOENDRC(IERROR, dl21_grp_key_copy);
    if(pbcext_element_G2_set(dl21_dst->g2, dl21_src->g2) == IERROR)
      GOTOENDRC(IERROR, dl21_grp_key_copy);
  }

  if(dl21_src->h1) {  
    if(!(dl21_dst->h1 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, dl21_grp_key_copy);
    if(pbcext_element_G1_set(dl21_dst->h1, dl21_src->h1) == IERROR)
      GOTOENDRC(IERROR, dl21_grp_key_copy);
  }

  if(dl21_src->h2) {  
    if(!(dl21_dst->h2 = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, dl21_grp_key_copy);
    if(pbcext_element_G1_set(dl21_dst->h2, dl21_src->h2) == IERROR)
      GOTOENDRC(IERROR, dl21_grp_key_copy);
  }

  if(dl21_src->ipk) {  
    if(!(dl21_dst->ipk = pbcext_element_G2_init()))
      GOTOENDRC(IERROR, dl21_grp_key_copy);
    if(pbcext_element_G2_set(dl21_dst->ipk, dl21_src->ipk) == IERROR)
      GOTOENDRC(IERROR, dl21_grp_key_copy);
  }
  
 dl21_grp_key_copy_end:

  if (rc == IERROR) {
    pbcext_element_G1_free(dl21_dst->g1); dl21_dst->g1 = NULL;
    pbcext_element_G2_free(dl21_dst->g2); dl21_dst->g2 = NULL;
    pbcext_element_G1_free(dl21_dst->h1); dl21_dst->h1 = NULL;
    pbcext_element_G1_free(dl21_dst->h2); dl21_dst->h2 = NULL;
    pbcext_element_G2_free(dl21_dst->ipk); dl21_dst->ipk = NULL;
  }
  
  return rc;

}

int dl21_grp_key_get_size(groupsig_key_t *key) {

  dl21_grp_key_t *dl21_key;
  int size;
  uint64_t sg1, sg2, sh1, sh2, sipk;
  
  if(!key || key->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_grp_key_get_size", __LINE__, LOGERROR);
    return -1;
  }

  dl21_key = key->key;
  sg1 = sg2 = sh1 = sh2 = sipk = 0;

  if (dl21_key->g1) { if(pbcext_element_G1_byte_size(&sg1) == IERROR) return -1; }
  if (dl21_key->g2) { if(pbcext_element_G2_byte_size(&sg2) == IERROR) return -1; }
  if (dl21_key->h1) { if(pbcext_element_G1_byte_size(&sh1) == IERROR) return -1; }
  if (dl21_key->h2) { if(pbcext_element_G1_byte_size(&sh2) == IERROR) return -1; }
  if (dl21_key->ipk) { if(pbcext_element_G2_byte_size(&sipk) == IERROR) return -1; }

  if (sg1 + sg2 + sh1 + sh2 + sipk + sizeof(int)*5+2 > INT_MAX)
    return -1;
  size = (int) sg1 + sg2 + sh1 + sh2 + sipk + sizeof(int)*5+2;
  
  return size;

}

int dl21_grp_key_export(byte_t **bytes,
			uint32_t *size,
			groupsig_key_t *key) {

  dl21_grp_key_t *dl21_key;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int _size, ctr, rc;

  if(!bytes ||
     !size ||
     !key || key->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_grp_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  dl21_key = key->key;
  
  /* Get the number of bytes to represent the key */
  if ((_size = dl21_grp_key_get_size(key)) == -1) {
    return IERROR;
  }

  if(!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }  

  /* Dump GROUPSIG_DL21_CODE */
  _bytes[ctr++] = GROUPSIG_DL21_CODE;

  /* Dump key type */
  _bytes[ctr++] = GROUPSIG_KEY_GRPKEY;
  
  /* Dump g1 */
  if(dl21_key->g1) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, dl21_key->g1) == IERROR)
      GOTOENDRC(IERROR, dl21_grp_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump g2 */
  if(dl21_key->g2) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G2_bytes(&__bytes, &len, dl21_key->g2) == IERROR)
      GOTOENDRC(IERROR, dl21_grp_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump h1 */
  if(dl21_key->h1) {
    __bytes = &_bytes[ctr];    
   if(pbcext_dump_element_G1_bytes(&__bytes, &len, dl21_key->h1) == IERROR)
     GOTOENDRC(IERROR, dl21_grp_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump h2 */
  if(dl21_key->h2) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G1_bytes(&__bytes, &len, dl21_key->h2) == IERROR)
      GOTOENDRC(IERROR, dl21_grp_key_export);
    ctr += len;
  } else { ctr += sizeof(int); }

  /* Dump ipk */
  if(dl21_key->ipk) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_G2_bytes(&__bytes, &len, dl21_key->ipk) == IERROR)
      GOTOENDRC(IERROR, dl21_grp_key_export);
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
    LOG_ERRORCODE_MSG(&logger, __FILE__, "dl21_grp_key_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, dl21_grp_key_export);
  }

  *size = ctr;

 dl21_grp_key_export_end:

  if (rc == IERROR) {
    if(_bytes) { mem_free(_bytes); _bytes = NULL; }
  }

  return rc;

}

groupsig_key_t* dl21_grp_key_import(byte_t *source, uint32_t size) {

  groupsig_key_t *key;
  dl21_grp_key_t *dl21_key;
  uint64_t len;
  byte_t scheme, type;
  int rc, ctr;

  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "dl21_grp_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;
  
  if(!(key = dl21_grp_key_init())) {
    return NULL;
  }

  dl21_key = key->key;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "dl21_grp_key_import", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, dl21_grp_key_import);
  }

  /* Next byte: key type */
  type = source[ctr++];
  if(type != GROUPSIG_KEY_GRPKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "dl21_grp_key_import", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, dl21_grp_key_import);
  }

  /* Get g1 */
  if(!(dl21_key->g1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21_grp_key_import);
  if(pbcext_get_element_G1_bytes(dl21_key->g1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21_grp_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(dl21_key->g1); dl21_key->g1 = NULL;
  } else {
    ctr += len;
  }
  
  /* Get g2 */
  if(!(dl21_key->g2 = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, dl21_grp_key_import);
  if(pbcext_get_element_G2_bytes(dl21_key->g2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21_grp_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G2_free(dl21_key->g2); dl21_key->g2 = NULL;
  } else {
    ctr += len;
  }
  
  /* Get h1 */
  if(!(dl21_key->h1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21_grp_key_import);
  if(pbcext_get_element_G1_bytes(dl21_key->h1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21_grp_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(dl21_key->h1); dl21_key->h1 = NULL;
  } else {
    ctr += len;
  }
  
  /* Get h2 */
  if(!(dl21_key->h2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21_grp_key_import);
  if(pbcext_get_element_G1_bytes(dl21_key->h2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21_grp_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G1_free(dl21_key->h2); dl21_key->h2 = NULL;
  } else {
    ctr += len;
  }
  
  /* Get ipk */
  if(!(dl21_key->ipk = pbcext_element_G2_init()))
    GOTOENDRC(IERROR, dl21_grp_key_import);
  if(pbcext_get_element_G2_bytes(dl21_key->ipk, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21_grp_key_import);
  if(!len) {
    ctr += sizeof(int); // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    pbcext_element_G2_free(dl21_key->ipk); dl21_key->ipk = NULL;
  } else {
    ctr += len;
  }

 dl21_grp_key_import_end:
  
  if(rc == IERROR && key) { dl21_grp_key_free(key); key = NULL; }
  if(rc == IOK) return key;
  return NULL;  

}

char* dl21_grp_key_to_string(groupsig_key_t *key) {

  /* return skey; */
  fprintf(stderr, "@TODO dl21_grp_key_to_string not implemented.\n");
  return NULL;

}

/* grp_key.c ends here */
