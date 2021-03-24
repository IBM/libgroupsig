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
#include "groupsig/gl19/signature.h"

groupsig_signature_t* gl19_signature_init() {

  groupsig_signature_t *sig;
  gl19_signature_t *gl19_sig;

  gl19_sig = NULL;

  /* Initialize the signature contents */
  if(!(sig = (groupsig_signature_t *) mem_malloc(sizeof(groupsig_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "gl19_signature_init", __LINE__, errno, 
		  LOGERROR);
  }

  if(!(gl19_sig = (gl19_signature_t *) mem_malloc(sizeof(gl19_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "gl19_signature_init", __LINE__, errno, 
		  LOGERROR);
    return NULL;
  }

  sig->scheme = GROUPSIG_GL19_CODE;
  sig->sig = gl19_sig;

  return sig;

}

int gl19_signature_free(groupsig_signature_t *sig) {

  gl19_signature_t *gl19_sig;

  if(!sig || sig->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gl19_signature_free", __LINE__,
		   "Nothing to free.", LOGWARN);    
    return IOK;
  }

  if(sig->sig) {
    gl19_sig = sig->sig;
    pbcext_element_G1_free(gl19_sig->AA); gl19_sig->AA = NULL;
    pbcext_element_G1_free(gl19_sig->A_); gl19_sig->A_ = NULL;
    pbcext_element_G1_free(gl19_sig->d); gl19_sig->d = NULL;
    spk_rep_free(gl19_sig->pi); gl19_sig->pi = NULL;
    pbcext_element_G1_free(gl19_sig->nym1); gl19_sig->nym1 = NULL;
    pbcext_element_G1_free(gl19_sig->nym2); gl19_sig->nym2 = NULL;
    pbcext_element_G1_free(gl19_sig->ehy1); gl19_sig->ehy1 = NULL;
    pbcext_element_G1_free(gl19_sig->ehy2); gl19_sig->ehy2 = NULL;    
    mem_free(gl19_sig);
    gl19_sig = NULL;
  }
  
  mem_free(sig);

  return IOK;

}

int gl19_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src) {

  gl19_signature_t *gl19_dst, *gl19_src;
  int rc;

  if(!dst || dst->scheme != GROUPSIG_GL19_CODE ||
     !src || src->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_signature_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  gl19_dst = dst->sig;
  gl19_src = src->sig;
  rc = IOK;

  /* Copy the elements */
  if(!(gl19_dst->AA = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_signature_copy);
  if(pbcext_element_G1_set(gl19_dst->AA, gl19_src->AA) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_copy);
  
  if(!(gl19_dst->A_ = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_signature_copy);
  if(pbcext_element_G1_set(gl19_dst->A_, gl19_src->A_) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_copy);
  
  if(!(gl19_dst->d = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_signature_copy);
  if(pbcext_element_G1_set(gl19_dst->d, gl19_src->d) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_copy);

  if(!(gl19_dst->pi = spk_rep_init(gl19_src->pi->ns)))
    GOTOENDRC(IERROR, gl19_signature_copy);
  if(spk_rep_copy(gl19_dst->pi, gl19_src->pi) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_copy);

  if(!(gl19_dst->nym1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_signature_copy);
  if(pbcext_element_G1_set(gl19_dst->nym1, gl19_src->nym1) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_copy);

  if(!(gl19_dst->nym2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_signature_copy);
  if(pbcext_element_G1_set(gl19_dst->nym2, gl19_src->nym2) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_copy);

  if(!(gl19_dst->ehy1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_signature_copy);
  if(pbcext_element_G1_set(gl19_dst->ehy1, gl19_src->ehy1) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_copy);

  if(!(gl19_dst->ehy2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_signature_copy);
  if(pbcext_element_G1_set(gl19_dst->ehy2, gl19_src->ehy2) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_copy);

  gl19_dst->expiration = gl19_src->expiration;
  
 gl19_signature_copy_end:

  if (rc == IERROR) {
    if(gl19_dst->AA) {
      pbcext_element_G1_free(gl19_dst->AA);
      gl19_dst->AA = NULL;
    }
    if(gl19_dst->A_) {
      pbcext_element_G1_free(gl19_dst->A_);
      gl19_dst->A_ = NULL;
    }
    if(gl19_dst->d) {
      pbcext_element_G1_free(gl19_dst->d);
      gl19_dst->d = NULL;
    }
    if(gl19_dst->pi) {
      spk_rep_free(gl19_dst->pi);
      gl19_dst->pi = NULL;
    }
    if(gl19_dst->nym1) {
      pbcext_element_G1_free(gl19_dst->nym1);
      gl19_dst->nym1 = NULL;
    }
    if(gl19_dst->nym2) {
      pbcext_element_G1_free(gl19_dst->nym2);
      gl19_dst->nym2 = NULL;
    }
    if(gl19_dst->ehy1) {
      pbcext_element_G1_free(gl19_dst->ehy1);
      gl19_dst->ehy1 = NULL;
    }
    if(gl19_dst->ehy2) {
      pbcext_element_G1_free(gl19_dst->ehy2);
      gl19_dst->ehy2 = NULL;
    }    
    
  }
  
  return rc;

}

// @TODO this is not what I'd like from a to_string function.
// this should return a human readable string with the contents
// of the signature.
char* gl19_signature_to_string(groupsig_signature_t *sig) {

  uint32_t size;
  byte_t *bytes;
  char *str;
  
  if(!sig || sig->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "signature_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  bytes = NULL;
  if(gl19_signature_export(&bytes, &size, sig) == IERROR) return NULL;
  str = base64_encode(bytes, size, 1);
  mem_free(bytes); bytes = NULL;

  return str;

}

int gl19_signature_get_size(groupsig_signature_t *sig) {

  uint64_t sAA, sA_, sd, sc, ss, snym1, snym2, sehy1, sehy2;
  gl19_signature_t *gl19_sig;
  int size, i;
  
  if(!sig || sig->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_signature_get_size",
	       __LINE__, LOGERROR);
    return -1;
  }

  gl19_sig = sig->sig;

  if(pbcext_element_G1_byte_size(&sAA) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sA_) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sd) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sc) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&snym1) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&snym2) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sehy1) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sehy2) == IERROR) return -1;  

  if(sAA + sA_ + sd + sc + snym1 + snym2 + sehy1 + sehy2 +
     + sizeof(uint64_t) + sizeof(int)*8+1 > INT_MAX) return -1;
  size = (int) sAA + sA_ + sd + sc + snym1 + snym2 + sehy1 + sehy2 +
    sizeof(uint64_t) + sizeof(int)*8+1;

  for(i=0; i<gl19_sig->pi->ns; i++) {
    if(pbcext_element_Fr_byte_size(&ss) == IERROR)
      return -1;
    if (size + ss + sizeof(int) > INT_MAX) return -1;
    size += (int) ss + sizeof(int);
  }

  return size;    

}

int gl19_signature_export(byte_t **bytes,
			  uint32_t *size,
			  groupsig_signature_t *sig) { 

  gl19_signature_t *gl19_sig;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int rc, ctr, _size;
  uint16_t i;
  
  if(!sig || sig->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_signature_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  gl19_sig = sig->sig;

  if ((_size = gl19_signature_get_size(sig)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }  
  
   /* Dump GROUPSIG_GL19_CODE */
  _bytes[ctr++] = GROUPSIG_GL19_CODE;

  /* Dump AA */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_sig->AA) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_export);
  ctr += len;

  /* Dump A_ */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_sig->A_) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_export);
  ctr += len;  

  /* Dump d */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_sig->d) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_export);
  ctr += len;  
  
  /* Dump spk */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, gl19_sig->pi->c) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_export);
  ctr += len;  

  for(i=0; i<gl19_sig->pi->ns; i++) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, gl19_sig->pi->s[i]) == IERROR)
      GOTOENDRC(IERROR, gl19_signature_export);
    ctr += len;      
  }
  
  /* Dump nym1 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_sig->nym1) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_export);
  ctr += len;

  /* Dump nym2 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_sig->nym2) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_export);
  ctr += len;

  /* Dump ehy1 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_sig->ehy1) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_export);
  ctr += len;

  /* Dump ehy2 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, gl19_sig->ehy2) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_export);
  ctr += len;

  /* Dump expiration */
  memcpy(&_bytes[ctr], &gl19_sig->expiration, sizeof(uint64_t));
  ctr += sizeof(uint64_t);

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "gl19_signature_export", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, gl19_signature_export);
  }

  *size = ctr;

 gl19_signature_export_end:
  
  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  return rc;

}

groupsig_signature_t* gl19_signature_import(byte_t *source, uint32_t size) {

  groupsig_signature_t *sig;
  gl19_signature_t *gl19_sig;
  uint64_t len;
  uint16_t i;
  int rc, ctr;
  uint8_t scheme;

  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "gl19_signature_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(sig = gl19_signature_init())) {
    return NULL;
  }

  gl19_sig = sig->sig;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != sig->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "gl19_signature_import", __LINE__, 
		      EDQUOT, "Unexpected signature scheme.", LOGERROR);
    GOTOENDRC(IERROR, gl19_signature_import);
  }  

  /* Get AA */
  if(!(gl19_sig->AA = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_signature_import);
  if(pbcext_get_element_G1_bytes(gl19_sig->AA, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }

  /* Get A_ */
  if(!(gl19_sig->A_ = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_signature_import);
  if(pbcext_get_element_G1_bytes(gl19_sig->A_, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }  

  /* Get d */
  if(!(gl19_sig->d = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_signature_import);
  if(pbcext_get_element_G1_bytes(gl19_sig->d, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }
  
  /* Get spk */
  if(!(gl19_sig->pi = spk_rep_init(8)))
    GOTOENDRC(IERROR, gl19_signature_import);

  if(!(gl19_sig->pi->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, gl19_signature_import);
  if(pbcext_get_element_Fr_bytes(gl19_sig->pi->c, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }

  for(i=0; i<gl19_sig->pi->ns; i++) {
    if(!(gl19_sig->pi->s[i] = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, gl19_signature_import);
    if(pbcext_get_element_Fr_bytes(gl19_sig->pi->s[i], &len, &source[ctr]) == IERROR)
      GOTOENDRC(IERROR, gl19_signature_import);  
    if (!len) {
      ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    } else {
      ctr += len;
    }
  }
  
  /* Get nym1 */
  if(!(gl19_sig->nym1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_signature_import);
  if(pbcext_get_element_G1_bytes(gl19_sig->nym1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }

  /* Get nym2 */
  if(!(gl19_sig->nym2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_signature_import);
  if(pbcext_get_element_G1_bytes(gl19_sig->nym2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }

  /* Get ehy1 */
  if(!(gl19_sig->ehy1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_signature_import);
  if(pbcext_get_element_G1_bytes(gl19_sig->ehy1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }

  /* Get ehy2 */
  if(!(gl19_sig->ehy2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, gl19_signature_import);
  if(pbcext_get_element_G1_bytes(gl19_sig->ehy2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, gl19_signature_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }

  /* Get expiration */
  memcpy(&gl19_sig->expiration, &source[ctr], sizeof(uint64_t));
  ctr += sizeof(uint64_t);

 gl19_signature_import_end:

  if(rc == IERROR && sig) { gl19_signature_free(sig); sig = NULL; }
  if(rc == IOK) return sig;
  return NULL;

}

/* signature.c ends here */
