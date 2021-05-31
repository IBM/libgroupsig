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
#include "dl21seq.h"
#include "groupsig/dl21seq/signature.h"

groupsig_signature_t* dl21seq_signature_init() {

  groupsig_signature_t *sig;
  dl21seq_signature_t *dl21seq_sig;

  dl21seq_sig = NULL;

  /* Initialize the signature contents */
  if(!(sig = (groupsig_signature_t *) mem_malloc(sizeof(groupsig_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "dl21seq_signature_init", __LINE__, errno, 
		  LOGERROR);
  }

  if(!(dl21seq_sig = (dl21seq_signature_t *) mem_malloc(sizeof(dl21seq_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "dl21seq_signature_init", __LINE__, errno, 
		  LOGERROR);
    return NULL;
  }

  sig->scheme = GROUPSIG_DL21SEQ_CODE;
  sig->sig = dl21seq_sig;

  return sig;

}

int dl21seq_signature_free(groupsig_signature_t *sig) {

  dl21seq_signature_t *dl21seq_sig;

  if(!sig || sig->scheme != GROUPSIG_DL21SEQ_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "dl21seq_signature_free", __LINE__,
		   "Nothing to free.", LOGWARN);    
    return IOK;
  }

  if(sig->sig) {
    dl21seq_sig = sig->sig;
    pbcext_element_G1_free(dl21seq_sig->AA); dl21seq_sig->AA = NULL;
    pbcext_element_G1_free(dl21seq_sig->A_); dl21seq_sig->A_ = NULL;
    pbcext_element_G1_free(dl21seq_sig->d); dl21seq_sig->d = NULL;
    spk_rep_free(dl21seq_sig->pi); dl21seq_sig->pi = NULL;
    pbcext_element_G1_free(dl21seq_sig->nym); dl21seq_sig->nym = NULL;
    if (dl21seq_sig->seq) {
      if (dl21seq_sig->seq->seq1) {
	mem_free(dl21seq_sig->seq->seq1);
	dl21seq_sig->seq->seq1 = NULL;
      }
      if (dl21seq_sig->seq->seq2) {
	mem_free(dl21seq_sig->seq->seq2);
	dl21seq_sig->seq->seq2 = NULL;
      }
      if (dl21seq_sig->seq->seq3) {
	mem_free(dl21seq_sig->seq->seq3);
	dl21seq_sig->seq->seq3 = NULL;
      }
      mem_free(dl21seq_sig->seq);
      dl21seq_sig->seq = NULL;
    }
    mem_free(dl21seq_sig);
    dl21seq_sig = NULL;
  }
  
  mem_free(sig);

  return IOK;

}

int dl21seq_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src) {

  dl21seq_signature_t *dl21seq_dst, *dl21seq_src;
  int rc;

  if(!dst || dst->scheme != GROUPSIG_DL21SEQ_CODE ||
     !src || src->scheme != GROUPSIG_DL21SEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_signature_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  dl21seq_dst = dst->sig;
  dl21seq_src = src->sig;
  rc = IOK;

  /* Copy the elements */
  if(!(dl21seq_dst->AA = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21seq_signature_copy);
  if(pbcext_element_G1_set(dl21seq_dst->AA, dl21seq_src->AA) == IERROR)
    GOTOENDRC(IERROR, dl21seq_signature_copy);
  
  if(!(dl21seq_dst->A_ = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21seq_signature_copy);
  if(pbcext_element_G1_set(dl21seq_dst->A_, dl21seq_src->A_) == IERROR)
    GOTOENDRC(IERROR, dl21seq_signature_copy);
  
  if(!(dl21seq_dst->d = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21seq_signature_copy);
  if(pbcext_element_G1_set(dl21seq_dst->d, dl21seq_src->d) == IERROR)
    GOTOENDRC(IERROR, dl21seq_signature_copy);

  if(!(dl21seq_dst->pi = spk_rep_init(dl21seq_src->pi->ns)))
    GOTOENDRC(IERROR, dl21seq_signature_copy);
  if(spk_rep_copy(dl21seq_dst->pi, dl21seq_src->pi) == IERROR)
    GOTOENDRC(IERROR, dl21seq_signature_copy);

  if(!(dl21seq_dst->nym = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21seq_signature_copy);
  if(pbcext_element_G1_set(dl21seq_dst->nym, dl21seq_src->nym) == IERROR)
    GOTOENDRC(IERROR, dl21seq_signature_copy);
  
 dl21seq_signature_copy_end:

  if (rc == IERROR) {
    if(dl21seq_dst->AA) {
      pbcext_element_G1_free(dl21seq_dst->AA);
      dl21seq_dst->AA = NULL;
    }
    if(dl21seq_dst->A_) {
      pbcext_element_G1_free(dl21seq_dst->A_);
      dl21seq_dst->A_ = NULL;
    }
    if(dl21seq_dst->d) {
      pbcext_element_G1_free(dl21seq_dst->d);
      dl21seq_dst->d = NULL;
    }
    if(dl21seq_dst->pi) {
      spk_rep_free(dl21seq_dst->pi);
      dl21seq_dst->pi = NULL;
    }    
    if(dl21seq_dst->nym) {
      pbcext_element_G1_free(dl21seq_dst->nym);
      dl21seq_dst->nym = NULL;
    }
    
  }
  
  return rc;

}

int dl21seq_signature_get_size(groupsig_signature_t *sig) {

  uint64_t sAA, sA_, sd, sc, ss, snym;
  dl21seq_signature_t *dl21seq_sig;
  int size, i;

  if (!sig) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_signature_get_size", __LINE__,
	       LOGERROR);
    return -1;
  }
  
  dl21seq_sig = sig->sig;

  if (pbcext_element_G1_byte_size(&sAA) == IERROR) return -1;
  if (pbcext_element_G1_byte_size(&sA_) == IERROR) return -1;
  if (pbcext_element_G1_byte_size(&sd) == IERROR) return -1;
  if (pbcext_element_Fr_byte_size(&sc) == IERROR) return -1;
  if (pbcext_element_G1_byte_size(&snym) == IERROR) return -1;

  if ((int) sAA + sA_ + sd + sc + snym + dl21seq_sig->seq->len1 +
      dl21seq_sig->seq->len2 + dl21seq_sig->seq->len3 + sizeof(uint64_t)*3 +
      sizeof(int)*5+1 > INT_MAX) return -1;
  
  size = (int) sAA + sA_ + sd + sc + snym + dl21seq_sig->seq->len1 +
    dl21seq_sig->seq->len2 + dl21seq_sig->seq->len3 + sizeof(uint64_t)*3 +
    sizeof(int)*5+1;

  for (i=0; i<dl21seq_sig->pi->ns; i++) {
    if (pbcext_element_Fr_byte_size(&ss) == IERROR)
      return -1;
    if (size + (int) ss + sizeof(int) > INT_MAX) return -1;
    size += (int) ss + sizeof(int);
  }

  return size;

}

int dl21seq_signature_export(byte_t **bytes,
			     uint32_t *size,
			     groupsig_signature_t *sig) {

  dl21seq_signature_t *dl21seq_sig;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int rc, ctr, _size;
  uint16_t i;
  
  if(!sig || sig->scheme != GROUPSIG_DL21SEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_signature_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  dl21seq_sig = sig->sig;

  if ((_size = dl21seq_signature_get_size(sig)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }  
  
   /* Dump GROUPSIG_DL21SEQ_CODE */
  _bytes[ctr++] = GROUPSIG_DL21SEQ_CODE;

  /* Dump AA */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, dl21seq_sig->AA) == IERROR)
    GOTOENDRC(IERROR, dl21seq_signature_export);
  ctr += len;

  /* Dump A_ */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, dl21seq_sig->A_) == IERROR)
    GOTOENDRC(IERROR, dl21seq_signature_export);
  ctr += len;  

  /* Dump d */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, dl21seq_sig->d) == IERROR)
    GOTOENDRC(IERROR, dl21seq_signature_export);
  ctr += len;
  
  /* Dump spk */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, dl21seq_sig->pi->c) == IERROR)
    GOTOENDRC(IERROR, dl21seq_signature_export);
  ctr += len;  

  for(i=0; i<dl21seq_sig->pi->ns; i++) {
    __bytes = &_bytes[ctr];
    if(pbcext_dump_element_Fr_bytes(&__bytes, &len, dl21seq_sig->pi->s[i]) == IERROR)
      GOTOENDRC(IERROR, dl21seq_signature_export);
    ctr += len;      
  }
  
  /* Dump nym */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, dl21seq_sig->nym) == IERROR)
    GOTOENDRC(IERROR, dl21seq_signature_export);
  ctr += len;

  /* Dump len1 */
  memcpy(&_bytes[ctr], &dl21seq_sig->seq->len1, sizeof(uint64_t));
  ctr += sizeof(uint64_t);

  /* Get seq1 */
  memcpy(&_bytes[ctr], &dl21seq_sig->seq->seq1, dl21seq_sig->seq->len1);
  ctr += dl21seq_sig->seq->len1;

  /* Dump len2 */
  memcpy(&_bytes[ctr], &dl21seq_sig->seq->len2, sizeof(uint64_t));
  ctr += sizeof(uint64_t);

  /* Get seq2 */
  memcpy(&_bytes[ctr], &dl21seq_sig->seq->seq2, dl21seq_sig->seq->len2);
  ctr += dl21seq_sig->seq->len2;

  /* Dump len3 */
  memcpy(&_bytes[ctr], &dl21seq_sig->seq->len2, sizeof(uint64_t));
  ctr += sizeof(uint64_t);

  /* Get seq3 */
  memcpy(&_bytes[ctr], &dl21seq_sig->seq->seq2, dl21seq_sig->seq->len2);
  ctr += dl21seq_sig->seq->len2;  

  /* Prepare the return */
  if(!*bytes) {
    *bytes = _bytes;
  } else {
    memcpy(*bytes, _bytes, ctr);
    mem_free(_bytes); _bytes = NULL;
  }

  /* Sanity check */
  if (ctr != _size) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "dl21seq_signature_export", __LINE__, 
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    GOTOENDRC(IERROR, dl21seq_signature_export);
  }

  *size = ctr;

 dl21seq_signature_export_end:
  
  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  return rc;   

}

groupsig_signature_t* dl21seq_signature_import(byte_t *source, uint32_t size) {

  groupsig_signature_t *sig;
  dl21seq_signature_t *dl21seq_sig;
  uint64_t len;
  uint16_t i;
  int rc, ctr;
  uint8_t scheme;

  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "dl21seq_signature_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(sig = dl21seq_signature_init())) {
    return NULL;
  }

  dl21seq_sig = sig->sig;
  
  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != sig->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "dl21seq_signature_import", __LINE__, 
		      EDQUOT, "Unexpected signature scheme.", LOGERROR);
    GOTOENDRC(IERROR, dl21seq_signature_import);
  }  

  /* Get AA */
  if(!(dl21seq_sig->AA = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21seq_signature_import);
  if(pbcext_get_element_G1_bytes(dl21seq_sig->AA, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21seq_signature_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }

  /* Get A_ */
  if(!(dl21seq_sig->A_ = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21seq_signature_import);
  if(pbcext_get_element_G1_bytes(dl21seq_sig->A_, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21seq_signature_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }  

  /* Get d */
  if(!(dl21seq_sig->d = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21seq_signature_import);
  if(pbcext_get_element_G1_bytes(dl21seq_sig->d, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21seq_signature_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }

  /* Get spk */
  if(!(dl21seq_sig->pi = spk_rep_init(6)))
    GOTOENDRC(IERROR, dl21seq_signature_import);

  if(!(dl21seq_sig->pi->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, dl21seq_signature_import);
  if(pbcext_get_element_Fr_bytes(dl21seq_sig->pi->c, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21seq_signature_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }

  for(i=0; i<dl21seq_sig->pi->ns; i++) {
    if(!(dl21seq_sig->pi->s[i] = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, dl21seq_signature_import);
    if(pbcext_get_element_Fr_bytes(dl21seq_sig->pi->s[i], &len, &source[ctr]) == IERROR)
      GOTOENDRC(IERROR, dl21seq_signature_import);  
    if (!len) {
      ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
    } else {
      ctr += len;
    }
  }
  
  /* Get nym */
  if(!(dl21seq_sig->nym = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, dl21seq_signature_import);
  if(pbcext_get_element_G1_bytes(dl21seq_sig->nym, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, dl21seq_signature_import);  
  if (!len) {
    ctr += sizeof(int);  // @TODO: this is an artifact of pbcext_get_element_XX_bytes
  } else {
    ctr += len;
  }

  dl21seq_sig->seq = (dl21seq_seqinfo_t *) mem_malloc(sizeof(dl21seq_seqinfo_t));
  if (!dl21seq_sig->seq) GOTOENDRC(IERROR, dl21seq_signature_import);
  
  /* Get len1 */
  memcpy(&dl21seq_sig->seq->len1, &source[ctr], sizeof(uint64_t));
  ctr += sizeof(uint64_t);

  /* Get seq1 */
  if (!(dl21seq_sig->seq->seq1 =
	(byte_t *) mem_malloc(sizeof(byte_t)*dl21seq_sig->seq->len1)))
    GOTOENDRC(IERROR, dl21seq_signature_import);  
  memcpy(dl21seq_sig->seq->seq1, &source[ctr], dl21seq_sig->seq->len1);
  ctr += dl21seq_sig->seq->len1;

  /* Get len2 */
  memcpy(&dl21seq_sig->seq->len2, &source[ctr], sizeof(uint64_t));
  ctr += sizeof(uint64_t);

  /* Get seq2 */
  if (!(dl21seq_sig->seq->seq2 =
	(byte_t *) mem_malloc(sizeof(byte_t)*dl21seq_sig->seq->len2)))
    GOTOENDRC(IERROR, dl21seq_signature_import);  
  memcpy(dl21seq_sig->seq->seq2, &source[ctr], dl21seq_sig->seq->len2);
  ctr += dl21seq_sig->seq->len2;

  /* Get len3 */
  memcpy(&dl21seq_sig->seq->len3, &source[ctr], sizeof(uint64_t));
  ctr += sizeof(uint64_t);

  /* Get seq3 */
  if (!(dl21seq_sig->seq->seq3 =
	(byte_t *) mem_malloc(sizeof(byte_t)*dl21seq_sig->seq->len3)))
    GOTOENDRC(IERROR, dl21seq_signature_import);  
  memcpy(dl21seq_sig->seq->seq3, &source[ctr], dl21seq_sig->seq->len3);
  ctr += dl21seq_sig->seq->len3;

 dl21seq_signature_import_end:

  if(rc == IERROR && sig) { dl21seq_signature_free(sig); sig = NULL; }
  if(rc == IOK) return sig;
  return NULL;  

}

char* dl21seq_signature_to_string(groupsig_signature_t *sig) {

  uint32_t size;
  byte_t *bytes;
  char *str;
  
  if(!sig || sig->scheme != GROUPSIG_DL21SEQ_CODE) {
    LOG_EINVAL(&logger, __FILE__, "signature_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  bytes = NULL;
  if(dl21seq_signature_export(&bytes, &size, sig) == IERROR) return NULL;
  str = base64_encode(bytes, size, 1);
  mem_free(bytes); bytes = NULL;

  return str;

}

/* signature.c ends here */
