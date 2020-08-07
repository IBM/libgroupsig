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
#include <math.h>
#include <openssl/sha.h>

#include "types.h"
#include "sysenv.h"
#include "gl19.h"
#include "logger.h"
#include "sys/mem.h"
#include "shim/base64.h"
#include "misc/misc.h"
#include "groupsig/gl19/blindsig.h"

groupsig_blindsig_t* gl19_blindsig_init() {

  groupsig_blindsig_t *sig;
  gl19_blindsig_t *gl19_sig;

  gl19_sig = NULL;

  /* Initialize the signature contents */
  if(!(sig = (groupsig_blindsig_t *) mem_malloc(sizeof(groupsig_blindsig_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "gl19_blindsig_init", __LINE__, errno, 
		  LOGERROR);
  }

  if(!(gl19_sig = (gl19_blindsig_t *) mem_malloc(sizeof(gl19_blindsig_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "gl19_blindsig_init", __LINE__, errno, 
		  LOGERROR);
    return NULL;
  }

  sig->scheme = GROUPSIG_GL19_CODE;
  sig->sig = gl19_sig;

  return sig;

}

int gl19_blindsig_free(groupsig_blindsig_t *sig) {

  gl19_blindsig_t *gl19_sig;

  if(!sig || sig->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gl19_blindsig_free", __LINE__,
		   "Nothing to free.", LOGWARN);    
    return IOK;
  }

  if(sig->sig) {
    gl19_sig = sig->sig;
    pbcext_element_G1_free(gl19_sig->nym1); gl19_sig->nym1 = NULL;
    pbcext_element_G1_free(gl19_sig->nym2); gl19_sig->nym2 = NULL;
    pbcext_element_G1_free(gl19_sig->nym3); gl19_sig->nym3 = NULL;
    pbcext_element_G1_free(gl19_sig->c1); gl19_sig->c1 = NULL;
    pbcext_element_G1_free(gl19_sig->c2); gl19_sig->c2 = NULL;
    mem_free(gl19_sig); 
    gl19_sig = NULL;
  }
  
  mem_free(sig);

  return IOK;

}

int gl19_blindsig_copy(groupsig_blindsig_t *dst, groupsig_blindsig_t *src) {

  gl19_blindsig_t *gl19_dst, *gl19_src;
  int rc;
  
  if(!dst || dst->scheme != GROUPSIG_GL19_CODE ||
     !src || src->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_blindsig_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  gl19_dst = dst->sig;
  gl19_src = src->sig;
  rc = IOK;
  
  /* Copy the elements */
  if(!(gl19_dst->nym1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_blindsig_copy);
  if(pbcext_element_G1_set(gl19_dst->nym1, gl19_src->nym1) == IERROR)
    GOTOENDRC(IERROR, gl19_blindsig_copy);

  if(!(gl19_dst->nym2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_blindsig_copy);
  if(pbcext_element_G1_set(gl19_dst->nym2, gl19_src->nym2) == IERROR)
    GOTOENDRC(IERROR, gl19_blindsig_copy);

  if(!(gl19_dst->nym3 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_blindsig_copy);
  if(pbcext_element_G1_set(gl19_dst->nym3, gl19_src->nym3) == IERROR)
    GOTOENDRC(IERROR, gl19_blindsig_copy);

  if(!(gl19_dst->c1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_blindsig_copy);
  if(pbcext_element_G1_set(gl19_dst->c1, gl19_src->c1) == IERROR)
    GOTOENDRC(IERROR, gl19_blindsig_copy);

  if(!(gl19_dst->c2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_blindsig_copy);
  if(pbcext_element_G1_set(gl19_dst->c2, gl19_src->c2) == IERROR)
    GOTOENDRC(IERROR, gl19_blindsig_copy);

 gl19_blindsig_copy_end:

  if (rc == IERROR) {

    if (gl19_dst->nym1) {
      pbcext_element_G1_free(gl19_dst->nym1);
      gl19_dst->nym1 = NULL;
    }
    if (gl19_dst->nym2) {
      pbcext_element_G1_free(gl19_dst->nym2);
      gl19_dst->nym2 = NULL;
    }
    if (gl19_dst->nym3) {
      pbcext_element_G1_free(gl19_dst->nym3);
      gl19_dst->nym3 = NULL;
    }
    if (gl19_dst->c1) {
      pbcext_element_G1_free(gl19_dst->c1);
      gl19_dst->c1 = NULL;
    }
    if (gl19_dst->c2) {
      pbcext_element_G1_free(gl19_dst->c2);
      gl19_dst->c2 = NULL;
    }

  }
  
  return IOK;

}

// @TODO this is not what I'd like from a to_string function.
// this should return a human readable string with the contents
// of the signature.
char* gl19_blindsig_to_string(groupsig_blindsig_t *sig) {

  uint32_t size;
  byte_t *bytes;
  char *str;
  
  if(!sig || sig->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "signature_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  bytes = NULL;
  if(gl19_blindsig_export(&bytes, &size, sig) == IERROR) return NULL;
  str = base64_encode(bytes, size, 1);
  mem_free(bytes); bytes = NULL;  
  
  return str;

}

int gl19_blindsig_get_size(groupsig_blindsig_t *sig) {

  uint64_t snym1, snym2, snym3, sc1, sc2;
  int size, i;
  
  if(!sig || sig->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_blindsig_get_size",
	       __LINE__, LOGERROR);
    return -1;
  }

  if(pbcext_element_G1_byte_size(&snym1) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&snym2) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&snym3) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sc1) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sc2) == IERROR) return -1;

  if(snym1 + snym2 + snym3 + sc1 + sc2 + sizeof(int)*5 + 1 > INT_MAX) return -1;
  size = (int) snym1 + snym2 + snym3 + sc1 + sc2 + sizeof(int)*5 + 1;

  return size;  

}

int gl19_blindsig_export(byte_t **bytes,
			 uint32_t *size,
			 groupsig_blindsig_t *sig) { 

  gl19_blindsig_t *gl19_sig;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int rc, ctr, _size;
  uint16_t i;
  uint8_t code;
  
  if(!bytes ||
     !size ||
     !sig || sig->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_blindsig_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  gl19_sig = sig->sig;

  if ((_size = gl19_blindsig_get_size(sig)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }  

   /* Dump GROUPSIG_GL19_CODE */
  code = GROUPSIG_GL19_CODE; 
  _bytes[ctr++] = code;

  /* Dump nym1 */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_sig->nym1) == IERROR)
    GOTOENDRC(IERROR, gl19_blindsig_export);
  ctr += len;  

  /* Dump nym2 */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_sig->nym2) == IERROR)
    GOTOENDRC(IERROR, gl19_blindsig_export);
  ctr += len;   

  /* Dump nym3 */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_sig->nym3) == IERROR)
    GOTOENDRC(IERROR, gl19_blindsig_export);
  ctr += len;   
  
  /* Dump c1 */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_sig->c1) == IERROR)
    GOTOENDRC(IERROR, gl19_blindsig_export);
  ctr += len;  

  /* Dump c2 */
  __bytes = &_bytes[ctr];  
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_sig->c2) == IERROR)
    GOTOENDRC(IERROR, gl19_blindsig_export);
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
    LOG_ERRORCODE_MSG(&logger, __FILE__, "gl19_blindsig_export", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, gl19_blindsig_export);
  }

  *size = ctr;

 gl19_blindsig_export_end:
  
  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  return rc;

}

groupsig_blindsig_t* gl19_blindsig_import(byte_t *source, uint32_t size) {

  groupsig_blindsig_t *sig;
  gl19_blindsig_t *gl19_sig;
  uint64_t len;
  int rc, ctr;
  uint16_t i;
  uint8_t scheme;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "signature_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(sig = gl19_blindsig_init())) {
    return NULL;
  }
  
  gl19_sig = sig->sig;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != sig->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "gl19_blindsig_import", __LINE__, 
		      EDQUOT, "Unexpected blindsig scheme.", LOGERROR);
    GOTOENDRC(IERROR, gl19_blindsig_import);
  }  
  
  /* Get nym1 */
  if(!(gl19_sig->nym1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_blindsig_import);
  if(pbcext_get_element_G1_bytes(gl19_sig->nym1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_blindsig_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }

  /* Get nym2 */
  if(!(gl19_sig->nym2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_blindsig_import);
  if(pbcext_get_element_G1_bytes(gl19_sig->nym2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_blindsig_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }

  /* Get nym3 */
  if(!(gl19_sig->nym3 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_blindsig_import);
  if(pbcext_get_element_G1_bytes(gl19_sig->nym3, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_blindsig_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }

  /* Get c1 */
  if(!(gl19_sig->c1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_blindsig_import);
  if(pbcext_get_element_G1_bytes(gl19_sig->c1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_blindsig_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }

  /* Get c2 */
  if(!(gl19_sig->c2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_blindsig_import);
  if(pbcext_get_element_G1_bytes(gl19_sig->c2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_blindsig_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }


 gl19_blindsig_import_end:

  if(rc == IERROR && sig) { gl19_blindsig_free(sig); sig = NULL; }
  if(rc == IOK) return sig;
  return NULL;

}

/* blindsig.c ends here */
