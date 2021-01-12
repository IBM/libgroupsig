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

#include "types.h"
#include "sysenv.h"
#include "sys/mem.h"
#include "shim/base64.h"
#include "shim/pbc_ext.h"
#include "misc/misc.h"
#include "ps16.h"
#include "groupsig/ps16/signature.h"

groupsig_signature_t* ps16_signature_init() {

  groupsig_signature_t *sig;
  ps16_signature_t *ps16_sig;

  ps16_sig = NULL;

  /* Initialize the signature contents */
  if(!(sig = (groupsig_signature_t *) mem_malloc(sizeof(groupsig_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "ps16_signature_init", __LINE__, errno, 
		  LOGERROR);
  }

  if(!(ps16_sig = (ps16_signature_t *) mem_malloc(sizeof(ps16_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "ps16_signature_init", __LINE__, errno, 
		  LOGERROR);
    return NULL;
  }

  sig->scheme = GROUPSIG_PS16_CODE;
  sig->sig = ps16_sig;

  return sig;

}

int ps16_signature_free(groupsig_signature_t *sig) {

  ps16_signature_t *ps16_sig;

  if(!sig || sig->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "ps16_signature_free", __LINE__,
		   "Nothing to free.", LOGWARN);    
    return IOK;
  }

  if(sig->sig) {
    ps16_sig = sig->sig;
    if(ps16_sig->sigma1) {
      pbcext_element_G1_free(ps16_sig->sigma1);
      ps16_sig->sigma1 = NULL;
    }
    if(ps16_sig->sigma2) {
      pbcext_element_G1_free(ps16_sig->sigma2);
      ps16_sig->sigma2 = NULL;
    }
    if(ps16_sig->c) {
      pbcext_element_Fr_free(ps16_sig->c);
      ps16_sig->c = NULL;
    }
    if(ps16_sig->s) {
      pbcext_element_Fr_free(ps16_sig->s);
      ps16_sig->s = NULL;
    }
    mem_free(ps16_sig); ps16_sig = NULL;
  }
  
  mem_free(sig); sig = NULL;

  return IOK;

}

int ps16_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src) {

  ps16_signature_t *ps16_dst, *ps16_src;
  int rc;

  if(!dst || dst->scheme != GROUPSIG_PS16_CODE ||
     !src || src->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_signature_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  ps16_dst = dst->sig;
  ps16_src = src->sig;
  rc = IOK;

  /* Copy the elements */
  if(!(ps16_dst->sigma1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ps16_signature_copy);
  if(pbcext_element_G1_set(ps16_dst->sigma1, ps16_src->sigma1) == IERROR)
    GOTOENDRC(IERROR, ps16_signature_copy);
  if(!(ps16_dst->sigma2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ps16_signature_copy);    
  if(pbcext_element_G1_set(ps16_dst->sigma2, ps16_src->sigma2) == IERROR)
    GOTOENDRC(IERROR, ps16_signature_copy);
  if(!(ps16_dst->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, ps16_signature_copy);    
  if(pbcext_element_Fr_set(ps16_dst->c, ps16_src->c) == IERROR)
    GOTOENDRC(IERROR, ps16_signature_copy);  
  if(!(ps16_dst->s = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, ps16_signature_copy);
  if(pbcext_element_Fr_set(ps16_dst->s, ps16_src->s) == IERROR)
    GOTOENDRC(IERROR, ps16_signature_copy);  

 ps16_signature_copy_end:

  if(rc == IERROR) {
    if(ps16_dst->sigma1) {
      pbcext_element_G1_free(ps16_dst->sigma1);
      ps16_dst->sigma1 = NULL;
    }
    if(ps16_dst->sigma2) {
      pbcext_element_G1_free(ps16_dst->sigma2);
      ps16_dst->sigma2 = NULL;
    }
    if(ps16_dst->c) {
      pbcext_element_Fr_free(ps16_dst->c);
      ps16_dst->c = NULL;
    }
    if(ps16_dst->s) {
      pbcext_element_Fr_free(ps16_dst->s);
      ps16_dst->s = NULL;
    }

  }
  
  return rc;

}

int ps16_signature_get_size(groupsig_signature_t *sig) {

  ps16_signature_t *ps16_sig;
  uint64_t size64, ssigma1, ssigma2, sc, ss;
  
  if(!sig || sig->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_signature_get_size",
	       __LINE__, LOGERROR);
    return -1;
  }

  ps16_sig = sig->sig;

  if(pbcext_element_G1_byte_size(&ssigma1) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&ssigma2) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sc) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&ss) == IERROR) return -1;
      
  size64 = sizeof(uint8_t) + sizeof(int)*4 + ssigma1 + ssigma2 +  sc + ss;

  if(size64 > INT_MAX) return -1;
  return (int) size64;

}

int ps16_signature_export(byte_t **bytes,
			  uint32_t *size,
			  groupsig_signature_t *sig) {

  ps16_signature_t *ps16_sig;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int rc, ctr, _size;
  uint16_t i;
  uint8_t code;
  
  if(!sig || sig->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "ps16_signature_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  ps16_sig = sig->sig;

  if ((_size = ps16_signature_get_size(sig)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }  
  
  /* Dump GROUPSIG_PS16_CODE */
  code = GROUPSIG_PS16_CODE;
  _bytes[ctr++] = code;

  /* Dump sigma1 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, ps16_sig->sigma1) == IERROR) 
    GOTOENDRC(IERROR, ps16_signature_export);
  ctr += len;  

  /* Dump sigma2 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, ps16_sig->sigma2) == IERROR) 
    GOTOENDRC(IERROR, ps16_signature_export);
  ctr += len;  

  /* Dump c */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, ps16_sig->c) == IERROR) 
    GOTOENDRC(IERROR, ps16_signature_export);
  ctr += len;

  /* Dump s */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, ps16_sig->s) == IERROR) 
    GOTOENDRC(IERROR, ps16_signature_export);
  ctr += len;  

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ps16_signature_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, ps16_signature_export);
  }
  
  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  *size = ctr;  

 ps16_signature_export_end:
  
  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  return rc;  

}

groupsig_signature_t* ps16_signature_import(byte_t *source, uint32_t size) {

  groupsig_signature_t *sig;
  ps16_signature_t *ps16_sig;
  uint64_t len;
  uint16_t i;
  int rc, ctr;
  uint8_t scheme;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "ps16_signature_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(sig = ps16_signature_init())) {
    return NULL;
  }
  
  ps16_sig = sig->sig;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != sig->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "ps16_signature_import", __LINE__, 
		      EDQUOT, "Unexpected signature scheme.", LOGERROR);
    GOTOENDRC(IERROR, ps16_signature_import);
  }

  /* Get sigma1 */
  if(!(ps16_sig->sigma1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ps16_signature_import);
  if(pbcext_get_element_G1_bytes(ps16_sig->sigma1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ps16_signature_import);
  ctr += len;

  /* Get sigma2 */
  if(!(ps16_sig->sigma2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, ps16_signature_import);
  if(pbcext_get_element_G1_bytes(ps16_sig->sigma2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ps16_signature_import);
  ctr += len;  

  /* Get c */
  if(!(ps16_sig->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, ps16_signature_import);
  if(pbcext_get_element_Fr_bytes(ps16_sig->c, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ps16_signature_import);
  ctr += len;

  /* Get s */
  if(!(ps16_sig->s = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, ps16_signature_import);
  if(pbcext_get_element_Fr_bytes(ps16_sig->s, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, ps16_signature_import);
  ctr += len;

 ps16_signature_import_end:

  if(rc == IERROR && sig) { ps16_signature_free(sig); sig = NULL; }
  if(rc == IOK) return sig;
  return NULL;  

}

// @TODO this is not what I'd like from a to_string function.
// this should return a human readable string with the contents
// of the signature.
char* ps16_signature_to_string(groupsig_signature_t *sig) {

  uint32_t size;
  byte_t *bytes;
  char *str;
  
  if(!sig || sig->scheme != GROUPSIG_PS16_CODE) {
    LOG_EINVAL(&logger, __FILE__, "signature_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  bytes = NULL;
  if(ps16_signature_export(&bytes, &size, sig) == IERROR) return NULL;
  str = base64_encode(bytes, size, 1);
  mem_free(bytes); bytes = NULL;

  return str;
}

/* signature.c ends here */
