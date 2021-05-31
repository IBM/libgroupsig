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
#include "misc/misc.h"
#include "dl21.h"
#include "groupsig/dl21/signature.h"

groupsig_signature_t* dl21_signature_init() {

  groupsig_signature_t *sig;
  dl21_signature_t *dl21_sig;

  dl21_sig = NULL;

  /* Initialize the signature contents */
  if(!(sig = (groupsig_signature_t *) mem_malloc(sizeof(groupsig_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "dl21_signature_init", __LINE__, errno, 
		  LOGERROR);
  }

  if(!(dl21_sig = (dl21_signature_t *) mem_malloc(sizeof(dl21_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "dl21_signature_init", __LINE__, errno, 
		  LOGERROR);
    return NULL;
  }

  sig->scheme = GROUPSIG_DL21_CODE;
  sig->sig = dl21_sig;

  return sig;

}

int dl21_signature_free(groupsig_signature_t *sig) {

  dl21_signature_t *dl21_sig;

  if(!sig || sig->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "dl21_signature_free", __LINE__,
		   "Nothing to free.", LOGWARN);    
    return IOK;
  }

  if(sig->sig) {
    dl21_sig = sig->sig;
    pbcext_element_G1_free(dl21_sig->AA); dl21_sig->AA = NULL;
    pbcext_element_G1_free(dl21_sig->A_); dl21_sig->A_ = NULL;
    pbcext_element_G1_free(dl21_sig->d); dl21_sig->d = NULL;
    spk_rep_free(dl21_sig->pi); dl21_sig->pi = NULL;
    pbcext_element_G1_free(dl21_sig->nym); dl21_sig->nym = NULL;
    mem_free(dl21_sig);
    dl21_sig = NULL;
  }
  
  mem_free(sig);

  return IOK;

}

int dl21_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src) {

  dl21_signature_t *dl21_dst, *dl21_src;
  int rc;

  if(!dst || dst->scheme != GROUPSIG_DL21_CODE ||
     !src || src->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_signature_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  dl21_dst = dst->sig;
  dl21_src = src->sig;
  rc = IOK;

  /* Copy the elements */
  if(!(dl21_dst->AA = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21_signature_copy);
  if(pbcext_element_G1_set(dl21_dst->AA, dl21_src->AA) == IERROR)
    GOTOENDRC(IERROR, dl21_signature_copy);
  
  if(!(dl21_dst->A_ = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21_signature_copy);
  if(pbcext_element_G1_set(dl21_dst->A_, dl21_src->A_) == IERROR)
    GOTOENDRC(IERROR, dl21_signature_copy);
  
  if(!(dl21_dst->d = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21_signature_copy);
  if(pbcext_element_G1_set(dl21_dst->d, dl21_src->d) == IERROR)
    GOTOENDRC(IERROR, dl21_signature_copy);

  if(!(dl21_dst->pi = spk_rep_init(dl21_src->pi->ns)))
    GOTOENDRC(IERROR, dl21_signature_copy);
  if(spk_rep_copy(dl21_dst->pi, dl21_src->pi) == IERROR)
    GOTOENDRC(IERROR, dl21_signature_copy);

  if(!(dl21_dst->nym = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21_signature_copy);
  if(pbcext_element_G1_set(dl21_dst->nym, dl21_src->nym) == IERROR)
    GOTOENDRC(IERROR, dl21_signature_copy);
  
 dl21_signature_copy_end:

  if (rc == IERROR) {
    if(dl21_dst->AA) {
      pbcext_element_G1_free(dl21_dst->AA);
      dl21_dst->AA = NULL;
    }
    if(dl21_dst->A_) {
      pbcext_element_G1_free(dl21_dst->A_);
      dl21_dst->A_ = NULL;
    }
    if(dl21_dst->d) {
      pbcext_element_G1_free(dl21_dst->d);
      dl21_dst->d = NULL;
    }
    if(dl21_dst->pi) {
      spk_rep_free(dl21_dst->pi);
      dl21_dst->pi = NULL;
    }
    if(dl21_dst->nym) {
      pbcext_element_G1_free(dl21_dst->nym);
      dl21_dst->nym = NULL;
    }
    
  }
  
  return rc;

}

int dl21_signature_get_size(groupsig_signature_t *sig) {

  uint64_t sAA, sA_, sd, sc, ss, snym;
  dl21_signature_t *dl21_sig;
  int size, i;

  if(!sig || sig->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_signature_get_size",
	       __LINE__, LOGERROR);
    return -1;
  }

  dl21_sig = sig->sig;

  if(pbcext_element_G1_byte_size(&sAA) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sA_) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sd) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sc) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&snym) == IERROR) return -1;

  if ((int) sAA + sA_ + sd + sc + snym + sizeof(int)*5+1 > INT_MAX) return -1;
  size = (int) sAA + sA_ + sd + sc + snym + sizeof(int)*5+1;

  for(i=0; i<dl21_sig->pi->ns; i++) {
    if(pbcext_element_Fr_byte_size(&ss) == IERROR)
      return -1;
    if (size + (int) ss + sizeof(int) > INT_MAX) return -1;
    size += (int) ss + sizeof(int);
  }
  
  return size;

}

int dl21_signature_export(byte_t **bytes,
			  uint32_t *size,
			  groupsig_signature_t *sig) { 

  dl21_signature_t *dl21_sig;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int rc, ctr, _size;
  uint16_t i;
  
  if(!sig || sig->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21_signature_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  dl21_sig = sig->sig;

  if ((_size = dl21_signature_get_size(sig)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }  

  
   /* Dump GROUPSIG_DL21_CODE */
  _bytes[ctr++] = GROUPSIG_DL21_CODE;

  /* Dump AA */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, dl21_sig->AA) == IERROR)
    GOTOENDRC(IERROR, dl21_signature_export);
  ctr += len;

  /* Dump A_ */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, dl21_sig->A_) == IERROR)
    GOTOENDRC(IERROR, dl21_signature_export);
  ctr += len;  

  /* Dump d */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, dl21_sig->d) == IERROR)
    GOTOENDRC(IERROR, dl21_signature_export);
  ctr += len;
  
  /* Dump spk */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, dl21_sig->pi->c) == IERROR)
    GOTOENDRC(IERROR, dl21_signature_export);
  ctr += len;  

  for(i=0; i<dl21_sig->pi->ns; i++) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, dl21_sig->pi->s[i]) == IERROR)
      GOTOENDRC(IERROR, dl21_signature_export);
    ctr += len;      
  }
  
  /* Dump nym */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, dl21_sig->nym) == IERROR)
    GOTOENDRC(IERROR, dl21_signature_export);
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
    LOG_ERRORCODE_MSG(&logger, __FILE__, "dl21_signature_export", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, dl21_signature_export);
  }

  *size = ctr;

 dl21_signature_export_end:
  
  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  return rc;  
  
}

groupsig_signature_t* dl21_signature_import(byte_t *source, uint32_t size) {

  groupsig_signature_t *sig;
  dl21_signature_t *dl21_sig;
  uint64_t len;
  uint16_t i;
  int rc, ctr;
  uint8_t scheme;

  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "dl21_signature_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(sig = dl21_signature_init())) {
    return NULL;
  }

  dl21_sig = sig->sig;
  
  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != sig->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "dl21_signature_import", __LINE__, 
		      EDQUOT, "Unexpected signature scheme.", LOGERROR);
    GOTOENDRC(IERROR, dl21_signature_import);
  }  

  /* Get AA */
  if(!(dl21_sig->AA = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21_signature_import);
  if(pbcext_get_element_G1_bytes(dl21_sig->AA, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21_signature_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }

  /* Get A_ */
  if(!(dl21_sig->A_ = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21_signature_import);
  if(pbcext_get_element_G1_bytes(dl21_sig->A_, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21_signature_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }  

  /* Get d */
  if(!(dl21_sig->d = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21_signature_import);
  if(pbcext_get_element_G1_bytes(dl21_sig->d, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21_signature_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }

  /* Get spk */
  if(!(dl21_sig->pi = spk_rep_init(6)))
    GOTOENDRC(IERROR, dl21_signature_import);

  if(!(dl21_sig->pi->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, dl21_signature_import);
  if(pbcext_get_element_Fr_bytes(dl21_sig->pi->c, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21_signature_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }

  for(i=0; i<dl21_sig->pi->ns; i++) {
    if(!(dl21_sig->pi->s[i] = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, dl21_signature_import);
    if(pbcext_get_element_Fr_bytes(dl21_sig->pi->s[i], &len, &source[ctr]) == IERROR)
      GOTOENDRC(IERROR, dl21_signature_import);  
    if (!len) {
      ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    } else {
      ctr += len;
    }
  }
  
  /* Get nym */
  if(!(dl21_sig->nym = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21_signature_import);
  if(pbcext_get_element_G1_bytes(dl21_sig->nym, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21_signature_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }

 dl21_signature_import_end:

  if(rc == IERROR && sig) { dl21_signature_free(sig); sig = NULL; }
  if(rc == IOK) return sig;
  return NULL;  

}

char* dl21_signature_to_string(groupsig_signature_t *sig) {

  uint32_t size;
  byte_t *bytes;
  char *str;
  
  if(!sig || sig->scheme != GROUPSIG_DL21_CODE) {
    LOG_EINVAL(&logger, __FILE__, "signature_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  bytes = NULL;
  if(dl21_signature_export(&bytes, &size, sig) == IERROR) return NULL;
  str = base64_encode(bytes, size, 1);
  mem_free(bytes); bytes = NULL;

  return str;

}

/* signature.c ends here */
