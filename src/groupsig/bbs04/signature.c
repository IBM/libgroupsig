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
#include "bbs04.h"
#include "groupsig/bbs04/signature.h"

/* Public functions */
groupsig_signature_t* bbs04_signature_init() {

  groupsig_signature_t *sig;
  bbs04_signature_t *bbs04_sig;

  bbs04_sig = NULL;

  /* Initialize the signature contents */
  if(!(sig = (groupsig_signature_t *) mem_malloc(sizeof(groupsig_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "bbs04_signature_init", __LINE__, errno, 
		  LOGERROR);
  }

  if(!(bbs04_sig = (bbs04_signature_t *) mem_malloc(sizeof(bbs04_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "bbs04_signature_init", __LINE__, errno, 
		  LOGERROR);
    return NULL;
  }

  sig->scheme = GROUPSIG_BBS04_CODE;
  sig->sig = bbs04_sig;

  return sig;

}

int bbs04_signature_free(groupsig_signature_t *sig) {

  bbs04_signature_t *bbs04_sig;

  if(!sig || sig->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "bbs04_signature_free", __LINE__,
		   "Nothing to free.", LOGWARN);    
    return IOK;
  }

  if(sig->sig) {
    bbs04_sig = sig->sig;
    if(bbs04_sig->T1) { pbcext_element_G1_free(bbs04_sig->T1); bbs04_sig->T1 = NULL; }
    if(bbs04_sig->T2) { pbcext_element_G1_free(bbs04_sig->T2); bbs04_sig->T2 = NULL; }
    if(bbs04_sig->T3) { pbcext_element_G1_free(bbs04_sig->T3); bbs04_sig->T3 = NULL; }
    if(bbs04_sig->c) { pbcext_element_Fr_free(bbs04_sig->c); bbs04_sig->c = NULL; }
    if(bbs04_sig->salpha) { pbcext_element_Fr_free(bbs04_sig->salpha); bbs04_sig->salpha = NULL; }
    if(bbs04_sig->sbeta) { pbcext_element_Fr_free(bbs04_sig->sbeta); bbs04_sig->sbeta = NULL; }
    if(bbs04_sig->sx) { pbcext_element_Fr_free(bbs04_sig->sx); bbs04_sig->sx = NULL; }
    if(bbs04_sig->sdelta1) { pbcext_element_Fr_free(bbs04_sig->sdelta1); bbs04_sig->sdelta1 = NULL; }
    if(bbs04_sig->sdelta2) { pbcext_element_Fr_free(bbs04_sig->sdelta2); bbs04_sig->sdelta2 = NULL; }
    mem_free(bbs04_sig); bbs04_sig = NULL;
  }
  
  mem_free(sig); sig = NULL;

  return IOK;

}

int bbs04_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src) {

  bbs04_signature_t *bbs04_dst, *bbs04_src;
  int rc;

  if(!dst || dst->scheme != GROUPSIG_BBS04_CODE ||
     !src || src->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_signature_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  bbs04_dst = dst->sig;
  bbs04_src = src->sig;
  rc = IOK;

  /* Copy the elements */
  if(!(bbs04_dst->T1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bbs04_signature_copy);
  if(pbcext_element_G1_set(bbs04_dst->T1, bbs04_src->T1) == IERROR)
    GOTOENDRC(IERROR, bbs04_signature_copy);
  if(!(bbs04_dst->T2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bbs04_signature_copy);    
  if(pbcext_element_G1_set(bbs04_dst->T2, bbs04_src->T2) == IERROR)
    GOTOENDRC(IERROR, bbs04_signature_copy);
  if(!(bbs04_dst->T3 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bbs04_signature_copy);
  if(pbcext_element_G1_set(bbs04_dst->T3, bbs04_src->T3) == IERROR)
    GOTOENDRC(IERROR, bbs04_signature_copy);  
  if(!(bbs04_dst->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_signature_copy);    
  if(pbcext_element_Fr_set(bbs04_dst->c, bbs04_src->c) == IERROR)
    GOTOENDRC(IERROR, bbs04_signature_copy);  
  if(!(bbs04_dst->salpha = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_signature_copy);
  if(pbcext_element_Fr_set(bbs04_dst->salpha, bbs04_src->salpha) == IERROR)
    GOTOENDRC(IERROR, bbs04_signature_copy);  
  if(!(bbs04_dst->sbeta = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_signature_copy);    
  if(pbcext_element_Fr_set(bbs04_dst->sbeta, bbs04_src->sbeta) == IERROR)
    GOTOENDRC(IERROR, bbs04_signature_copy);  
  if(!(bbs04_dst->sx = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_signature_copy);    
  if(pbcext_element_Fr_set(bbs04_dst->sx, bbs04_src->sx) == IERROR)
    GOTOENDRC(IERROR, bbs04_signature_copy);  
  if(!(bbs04_dst->sdelta1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_signature_copy);    
  if(pbcext_element_Fr_set(bbs04_dst->sdelta1, bbs04_src->sdelta1) == IERROR)
    GOTOENDRC(IERROR, bbs04_signature_copy);  
  if(!(bbs04_dst->sdelta2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_signature_copy);    
  if(pbcext_element_Fr_set(bbs04_dst->sdelta2, bbs04_src->sdelta2) == IERROR)
    GOTOENDRC(IERROR, bbs04_signature_copy);  

 bbs04_signature_copy_end:

  if(rc == IERROR) {
    if(bbs04_dst->T1) { pbcext_element_G1_free(bbs04_dst->T1); bbs04_dst->T1 = NULL; }
    if(bbs04_dst->T2) { pbcext_element_G1_free(bbs04_dst->T2); bbs04_dst->T2 = NULL; }
    if(bbs04_dst->T3) { pbcext_element_G1_free(bbs04_dst->T3); bbs04_dst->T3 = NULL; }
    if(bbs04_dst->c) { pbcext_element_Fr_free(bbs04_dst->c); bbs04_dst->c = NULL; }
    if(bbs04_dst->salpha) { pbcext_element_Fr_free(bbs04_dst->salpha); bbs04_dst->salpha = NULL; }
    if(bbs04_dst->sbeta) { pbcext_element_Fr_free(bbs04_dst->sbeta); bbs04_dst->sbeta = NULL; }
    if(bbs04_dst->sx) { pbcext_element_Fr_free(bbs04_dst->sx); bbs04_dst->sx = NULL; }
    if(bbs04_dst->sdelta1) { pbcext_element_Fr_free(bbs04_dst->sdelta1); bbs04_dst->sdelta1 = NULL; }
    if(bbs04_dst->sdelta2) { pbcext_element_Fr_free(bbs04_dst->sdelta2); bbs04_dst->sdelta2 = NULL; }
  }
  
  return rc;

}

int bbs04_signature_get_size(groupsig_signature_t *sig) {

  bbs04_signature_t *bbs04_sig;
  uint64_t size64, sT1, sT2, sT3, sc, ssalpha, ssbeta, ssx, ssdelta1, ssdelta2;
  
  if(!sig || sig->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_signature_get_size",
	       __LINE__, LOGERROR);
    return -1;
  }

  bbs04_sig = sig->sig;

  if(pbcext_element_G1_byte_size(&sT1) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sT2) == IERROR) return -1;
  if(pbcext_element_G1_byte_size(&sT3) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&sc) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&ssalpha) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&ssbeta) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&ssx) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&ssdelta1) == IERROR) return -1;
  if(pbcext_element_Fr_byte_size(&ssdelta2) == IERROR) return -1;
      
  size64 = sizeof(uint8_t)+sizeof(int)*9+
    sT1 + sT2 + sT3 + sc + ssalpha + ssbeta + ssx + ssdelta1 + ssdelta2;

  if(size64 > INT_MAX) return -1;
  return (int) size64;

}

int bbs04_signature_export(byte_t **bytes,
			   uint32_t *size,
			   groupsig_signature_t *sig) {

  bbs04_signature_t *bbs04_sig;
  byte_t *_bytes, *__bytes;
  uint64_t len;
  int rc, ctr, _size;
  uint16_t i;
  uint8_t code;
  
  if(!sig || sig->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_signature_export", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  ctr = 0;
  bbs04_sig = sig->sig;

  if ((_size = bbs04_signature_get_size(sig)) == -1) {
    return IERROR;
  }

  if (!(_bytes = mem_malloc(sizeof(byte_t)*_size))) {
    return IERROR;
  }  
  
  /* Dump GROUPSIG_BBS04_CODE */
  code = GROUPSIG_BBS04_CODE;
  _bytes[ctr++] = code;

  /* Dump T1 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, bbs04_sig->T1) == IERROR) 
    GOTOENDRC(IERROR, bbs04_signature_export);
  ctr += len;  

  /* Dump T2 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, bbs04_sig->T2) == IERROR) 
    GOTOENDRC(IERROR, bbs04_signature_export);
  ctr += len;  

  /* Dump T3 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_G1_bytes(&__bytes, &len, bbs04_sig->T3) == IERROR) 
    GOTOENDRC(IERROR, bbs04_signature_export);
  ctr += len;  

  /* Dump c */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bbs04_sig->c) == IERROR) 
    GOTOENDRC(IERROR, bbs04_signature_export);
  ctr += len;

  /* Dump salpha */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bbs04_sig->salpha) == IERROR) 
    GOTOENDRC(IERROR, bbs04_signature_export);
  ctr += len;  

  /* Dump sbeta */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bbs04_sig->sbeta) == IERROR) 
    GOTOENDRC(IERROR, bbs04_signature_export);
  ctr += len;

  /* Dump sx */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bbs04_sig->sx) == IERROR) 
    GOTOENDRC(IERROR, bbs04_signature_export);
  ctr += len;

  /* Dump sdelta1 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bbs04_sig->sdelta1) == IERROR)
    GOTOENDRC(IERROR, bbs04_signature_export);
  ctr += len;

  /* Dump sdelta2 */
  __bytes = &_bytes[ctr];
  if(pbcext_dump_element_Fr_bytes(&__bytes, &len, bbs04_sig->sdelta2) == IERROR)
    GOTOENDRC(IERROR, bbs04_signature_export);
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
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bbs04_signature_export", __LINE__, 
		      EDQUOT, "Unexpected size.", LOGERROR);
    GOTOENDRC(IERROR, bbs04_signature_export);
  }

  *size = ctr;  

 bbs04_signature_export_end:
  
  if (rc == IERROR && _bytes) { mem_free(_bytes); _bytes = NULL; }
  return rc;  

}

groupsig_signature_t* bbs04_signature_import(byte_t *source, uint32_t size) {

  groupsig_signature_t *sig;
  bbs04_signature_t *bbs04_sig;
  uint64_t len;
  uint16_t i;
  int rc, ctr;
  uint8_t scheme;
  
  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "bbs04_signature_import", __LINE__, LOGERROR);
    return NULL;
  }

  rc = IOK;
  ctr = 0;

  if(!(sig = bbs04_signature_init())) {
    return NULL;
  }
  
  bbs04_sig = sig->sig;

  /* First byte: scheme */
  scheme = source[ctr++];
  if(scheme != sig->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "bbs04_signature_import", __LINE__, 
		      EDQUOT, "Unexpected signature scheme.", LOGERROR);
    GOTOENDRC(IERROR, bbs04_signature_import);
  }

  /* Get T1 */
  if(!(bbs04_sig->T1 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bbs04_signature_import);
  if(pbcext_get_element_G1_bytes(bbs04_sig->T1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bbs04_signature_import);
  ctr += len;

  /* Get T2 */
  if(!(bbs04_sig->T2 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bbs04_signature_import);
  if(pbcext_get_element_G1_bytes(bbs04_sig->T2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bbs04_signature_import);
  ctr += len;  

  /* Get T3 */
  if(!(bbs04_sig->T3 = pbcext_element_G1_init()))
    GOTOENDRC(IERROR, bbs04_signature_import);
  if(pbcext_get_element_G1_bytes(bbs04_sig->T3, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bbs04_signature_import);
  ctr += len;

  /* Get c */
  if(!(bbs04_sig->c = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_signature_import);
  if(pbcext_get_element_Fr_bytes(bbs04_sig->c, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bbs04_signature_import);
  ctr += len;

  /* Get salpha */
  if(!(bbs04_sig->salpha = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_signature_import);
  if(pbcext_get_element_Fr_bytes(bbs04_sig->salpha, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bbs04_signature_import);
  ctr += len;

  /* Get sbeta */
  if(!(bbs04_sig->sbeta = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_signature_import);
  if(pbcext_get_element_Fr_bytes(bbs04_sig->sbeta, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bbs04_signature_import);
  ctr += len;

  /* Get sx */
  if(!(bbs04_sig->sx = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_signature_import);
  if(pbcext_get_element_Fr_bytes(bbs04_sig->sx, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bbs04_signature_import);
  ctr += len;

  /* Get sdelta1 */
  if(!(bbs04_sig->sdelta1 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_signature_import);
  if(pbcext_get_element_Fr_bytes(bbs04_sig->sdelta1, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bbs04_signature_import);
  ctr += len;

  /* Get sdelta2 */
  if(!(bbs04_sig->sdelta2 = pbcext_element_Fr_init()))
    GOTOENDRC(IERROR, bbs04_signature_import);
  if(pbcext_get_element_Fr_bytes(bbs04_sig->sdelta2, &len, &source[ctr]) == IERROR)
    GOTOENDRC(IERROR, bbs04_signature_import);
  ctr += len;

 bbs04_signature_import_end:

  if(rc == IERROR && sig) { bbs04_signature_free(sig); sig = NULL; }
  if(rc == IOK) return sig;
  return NULL;  

}

// @TODO this is not what I'd like from a to_string function.
// this should return a human readable string with the contents
// of the signature.
char* bbs04_signature_to_string(groupsig_signature_t *sig) {

  uint32_t size;
  byte_t *bytes;
  char *str;
  
  if(!sig || sig->scheme != GROUPSIG_BBS04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "signature_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  bytes = NULL;
  if(bbs04_signature_export(&bytes, &size, sig) == IERROR) return NULL;
  str = base64_encode(bytes, size, 1); // master had unsigned...
  mem_free(bytes); bytes = NULL;

  return str;
}

/* signature.c ends here */
