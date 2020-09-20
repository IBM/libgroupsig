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
#include "klap20.h"
#include "groupsig/klap20/signature.h"

groupsig_signature_t* klap20_signature_init() {

  groupsig_signature_t *sig;
  klap20_signature_t *klap20_sig;

  klap20_sig = NULL;

  /* Initialize the signature contents */
  if(!(sig = (groupsig_signature_t *) mem_malloc(sizeof(groupsig_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "klap20_signature_init", __LINE__, errno, 
		  LOGERROR);
  }

  if(!(klap20_sig = (klap20_signature_t *) mem_malloc(sizeof(klap20_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "klap20_signature_init", __LINE__, errno, 
		  LOGERROR);
    return NULL;
  }

  sig->scheme = GROUPSIG_KLAP20_CODE;
  sig->sig = klap20_sig;

  return sig;

}

int klap20_signature_free(groupsig_signature_t *sig) {

  klap20_signature_t *klap20_sig;

  if(!sig || sig->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "klap20_signature_free", __LINE__,
		   "Nothing to free.", LOGWARN);    
    return IOK;
  }

  if(sig->sig) {
    klap20_sig = sig->sig;
    if(klap20_sig->uu) {
      pbcext_element_G1_free(klap20_sig->uu);
      klap20_sig->uu = NULL;
    }
    if(klap20_sig->vv) {
      pbcext_element_G1_free(klap20_sig->vv);
      klap20_sig->vv = NULL;
    }
    if(klap20_sig->ww) {
      pbcext_element_G1_free(klap20_sig->ww);
      klap20_sig->ww = NULL;
    }
    if(klap20_sig->pi) {
      spk_dlog_free(klap20_sig->pi);
      klap20_sig->pi = NULL;
    }
    mem_free(klap20_sig); klap20_sig = NULL;
  }
  
  mem_free(sig); sig = NULL;

  return IOK;

}

int klap20_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src) {

  klap20_signature_t *klap20_dst, *klap20_src;
  int rc;

  if(!dst || dst->scheme != GROUPSIG_KLAP20_CODE ||
     !src || src->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_signature_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  klap20_dst = dst->sig;
  klap20_src = src->sig;
  rc = IOK;

  /* Copy the elements */
  if(!(klap20_dst->uu = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klap20_signature_copy);
  if(pbcext_element_G1_set(klap20_dst->uu, klap20_src->uu) == IERROR)
    GOTOENDRC(IERROR, klap20_signature_copy);
  if(!(klap20_dst->vv = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klap20_signature_copy);    
  if(pbcext_element_G1_set(klap20_dst->vv, klap20_src->vv) == IERROR)
    GOTOENDRC(IERROR, klap20_signature_copy);
  if(!(klap20_dst->ww = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klap20_signature_copy);    
  if(pbcext_element_G1_set(klap20_dst->ww, klap20_src->ww) == IERROR)
    GOTOENDRC(IERROR, klap20_signature_copy);  
  if(!(klap20_dst->pi = spk_dlog_init()))
    GOTOENDRC(IERROR, klap20_signature_copy);
  if(spk_dlog_copy(klap20_dst->pi, klap20_src->pi) == IERROR)
    GOTOENDRC(IERROR, klap20_signature_copy);
  
 klap20_signature_copy_end:

  if(rc == IERROR) {
    if(klap20_dst->uu) {
      pbcext_element_G1_free(klap20_dst->uu);
      klap20_dst->uu = NULL;
    }
    if(klap20_dst->vv) {
      pbcext_element_G1_free(klap20_dst->vv);
      klap20_dst->vv = NULL;
    }
    if(klap20_dst->ww) {
      pbcext_element_G1_free(klap20_dst->ww);
      klap20_dst->ww = NULL;
    }
    if(klap20_dst->pi) {
      spk_dlog_free(klap20_dst->pi);
      klap20_dst->pi = NULL;
    }

  }
  
  return rc;

}

int klap20_signature_get_size(groupsig_signature_t *sig) {

  klap20_signature_t *klap20_sig;
  uint64_t size64, suu, svv, sww, ss, sc;
  
  if(!sig || sig->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_signature_get_size",
	       __LINE__, LOGERROR);
    return -1;
  }

  suu = svv = sww = ss = sc = 0;

  klap20_sig = sig->sig;

  if(pbcext_element_G1_byte_size(&suu) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&svv) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sww) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sc) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&ss) == IERROR) return -1;  
      
  size64 = sizeof(uint8_t) + sizeof(int)*5 + suu + svv + sww +  sc + ss;

  if(size64 > INT_MAX) return -1;
  return (int) size64;

}

int klap20_signature_export(byte_t **bytes,
			  uint32_t *size,
			  groupsig_signature_t *sig) {

  klap20_signature_t *klap20_sig;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int rc, ctr, _size;
  uint8_t code;
  
  if(!sig || sig->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "klap20_signature_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  klap20_sig = sig->sig;

  if ((_size = klap20_signature_get_size(sig)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }  
  
  /* Dump GROUPSIG_KLAP20_CODE */
  code = GROUPSIG_KLAP20_CODE;
  _bytes[ctr++] = code;

  /* Dump uu */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, klap20_sig->uu) == IERROR) 
    GOTOENDRC(IERROR, klap20_signature_export);
  ctr += len;  

  /* Dump vv */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, klap20_sig->vv) == IERROR) 
    GOTOENDRC(IERROR, klap20_signature_export);
  ctr += len;

  /* Dump ww */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, klap20_sig->ww) == IERROR) 
    GOTOENDRC(IERROR, klap20_signature_export);
  ctr += len;    

  /* Dump pi->c */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, klap20_sig->pi->c) == IERROR) 
    GOTOENDRC(IERROR, klap20_signature_export);
  ctr += len;

  /* Dump pi->s */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, klap20_sig->pi->s) == IERROR) 
    GOTOENDRC(IERROR, klap20_signature_export);
  ctr += len;  

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "klap20_signature_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, klap20_signature_export);
  }
  
  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  *size = ctr;  

 klap20_signature_export_end:
  
  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  return rc;  

}

groupsig_signature_t* klap20_signature_import(byte_t *source, uint32_t size) {

  groupsig_signature_t *sig;
  klap20_signature_t *klap20_sig;
  uint64_t len;
  int rc, ctr;
  uint8_t scheme;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "klap20_signature_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(sig = klap20_signature_init())) {
    return NULL;
  }
  
  klap20_sig = sig->sig;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != sig->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "klap20_signature_import", __LINE__, 
		      EDQUOT, "Unexpected signature scheme.", LOGERROR);
    GOTOENDRC(IERROR, klap20_signature_import);
  }

  /* Get uu */
  if(!(klap20_sig->uu = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klap20_signature_import);
  if(pbcext_get_element_G1_bytes(klap20_sig->uu, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klap20_signature_import);
  ctr += len;

  /* Get vv */
  if(!(klap20_sig->vv = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klap20_signature_import);
  if(pbcext_get_element_G1_bytes(klap20_sig->vv, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klap20_signature_import);
  ctr += len;

  /* Get ww */
  if(!(klap20_sig->ww = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, klap20_signature_import);
  if(pbcext_get_element_G1_bytes(klap20_sig->ww, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klap20_signature_import);
  ctr += len;  

  /* Get c */
  if (!(klap20_sig->pi = spk_dlog_init()))
    GOTOENDRC(IERROR, klap20_signature_import);
  
  if(!(klap20_sig->pi->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, klap20_signature_import);
  if(pbcext_get_element_Fr_bytes(klap20_sig->pi->c, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klap20_signature_import);
  ctr += len;

  /* Get s */
  if(!(klap20_sig->pi->s = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, klap20_signature_import);
  if(pbcext_get_element_Fr_bytes(klap20_sig->pi->s, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, klap20_signature_import);
  ctr += len;

 klap20_signature_import_end:

  if(rc == IERROR && sig) { klap20_signature_free(sig); sig = NULL; }
  if(rc == IOK) return sig;
  return NULL;  

}

// @TODO this is not what I'd like from a to_string function.
// this should return a human readable string with the contents
// of the signature.
char* klap20_signature_to_string(groupsig_signature_t *sig) {

  uint32_t size;
  byte_t *bytes;
  char *str;
  
  if(!sig || sig->scheme != GROUPSIG_KLAP20_CODE) {
    LOG_EINVAL(&logger, __FILE__, "signature_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  bytes = NULL;
  if(klap20_signature_export(&bytes, &size, sig) == IERROR) return NULL;
  str = base64_encode(bytes, size, 1);
  mem_free(bytes); bytes = NULL;

  return str;
}

/* signature.c ends here */
