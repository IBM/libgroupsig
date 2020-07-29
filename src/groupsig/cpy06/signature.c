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
#include "sys/mem.h"
#include "wrappers/base64.h"
#include "wrappers/pbc_ext.h"
#include "misc/misc.h"
#include "exim.h"
#include "cpy06.h"
#include "groupsig/cpy06/signature.h"

/* Private functions */
/** 
 * @fn static int _is_supported_format(groupsig_signature_format_t format)
 * @brief Returns 1 if the specified format is supported by this scheme. 0 if not.
 *
 * @param[in] format The format to be "tested"
 * 
 * @return 1 if the specified format is supported, 0 if not.
 */
static int _is_supported_format(groupsig_signature_format_t format) {

  int i;

  for(i=0; i<CPY06_SUPPORTED_SIG_FORMATS_N; i++) {
    if(CPY06_SUPPORTED_SIG_FORMATS[i] == format) {
      return 1;
    }
  }

  return 0;

}

/**
 * @fn static int _get_size_bytearray_null(exim_t *obj)
 * @brief Returns the size in bytes of the exim wrapped object. The size will be
 * equal to the size of bytearray output by _export_fd() or created by
 * _import_fd().
 *
 * @param[in] obj The object to be sized.
 *
 * @return The size in bytes of the object contained in obj.
 */
static int _get_size_bytearray_null(exim_t* obj) {

  int size;

  if(!obj || !obj->eximable) {
    LOG_EINVAL(&logger, __FILE__, "_get_size_bytearray_null", __LINE__,
	       LOGERROR);
    return -1;
  }
  cpy06_signature_t *sig = obj->eximable;

  size = element_length_in_bytes(sig->T1)+element_length_in_bytes(sig->T2)+
    element_length_in_bytes(sig->T3)+element_length_in_bytes(sig->T4)+
    element_length_in_bytes(sig->T5)+element_length_in_bytes(sig->c)+
    element_length_in_bytes(sig->sr1)+element_length_in_bytes(sig->sr2)+
    element_length_in_bytes(sig->sd1)+element_length_in_bytes(sig->sd2)+
    element_length_in_bytes(sig->sx)+element_length_in_bytes(sig->st)+sizeof(int)*12+1;

  return size;  

}

/**
 * @fn static int _export_fd(exim_t* obj, FILE *fd)
 * @brief Exports a CPY06 proof to a bytearray,
 *
 * The format of the produced bytearray will be will be:
 *
 *    | CPY06_CODE | sizeof(c) | c | sizeof(s) | s|
 *
 * Where the first field is a byte and the sizeof fields are ints indicating
 * the number of bytes of the following field.
 *
 * @param[in] obj The exim wrapped signature to export.
 * @param[in] fd The destination file descriptor. Must be big enough to store the result.
 *
 * @return IOK or IERROR:
 */
static int _export_fd(exim_t* obj, FILE *fd) {
  uint8_t code;

  if(!obj || !obj->eximable || !fd) {
    LOG_EINVAL(&logger, __FILE__, "_export_fd", __LINE__, LOGERROR);
    return IERROR;
  }
  cpy06_signature_t *sig = (cpy06_signature_t*)obj->eximable;

  /* Dump GROUPSIG_CPY06_CODE */
  code = GROUPSIG_CPY06_CODE;
  if(fwrite(&code, sizeof(byte_t), 1, fd) != 1) {
      return IERROR;
  }

  /* Dump T1 */
  if(pbcext_dump_element_fd(sig->T1, fd) == IERROR) {
    return IERROR;
  }

  /* Dump T2 */
  if(pbcext_dump_element_fd(sig->T2, fd) == IERROR) {
    return IERROR;
  }

  /* Dump T3 */
  if(pbcext_dump_element_fd(sig->T3, fd) == IERROR) {
    return IERROR;
  }

  /* Dump T4 */
  if(pbcext_dump_element_fd(sig->T4, fd) == IERROR) {
    return IERROR;
  }

  /* Dump T5 */
  if(pbcext_dump_element_fd(sig->T5, fd) == IERROR) {
    return IERROR;
  }

  /* Dump c */
  if(pbcext_dump_element_fd(sig->c, fd) == IERROR) {
    return IERROR;
  }

  /* Dump sr1 */
  if(pbcext_dump_element_fd(sig->sr1, fd) == IERROR) {
    return IERROR;
  }

  /* Dump sr2 */
  if(pbcext_dump_element_fd(sig->sr2, fd) == IERROR) {
    return IERROR;
  }

  /* Dump sd1 */
  if(pbcext_dump_element_fd(sig->sd1, fd) == IERROR) {
    return IERROR;
  }

  /* Dump sd2 */
  if(pbcext_dump_element_fd(sig->sd2, fd) == IERROR) {
    return IERROR;
  }

  /* Dump sx */
  if(pbcext_dump_element_fd(sig->sx, fd) == IERROR) {
    return IERROR;
  }

  /* Dump st */
  if(pbcext_dump_element_fd(sig->st, fd) == IERROR) {
    return IERROR;
  }

  return IOK;
}

/**
 * @fn static char* _signature_to_string_b64(cpy06_signature_t *sig)
 * @brief Creates a representation of the given signature as a base64 string
 *
 * @param[in] sig The signature to convert.
 *
 * @return A pointer to the produced base64 string or NULL in case of error.
 */
static char* _signature_to_string_b64(cpy06_signature_t *sig) {
//  char *b64;
//  byte_t *bytes;
//  uint64_t /* offset, written,  */size;
//  b64 = NULL;

  return NULL;
}

/**
 * @fn static int _import_fd(FILE *fd, exim_t* obj)
 * @brief Import a representation of the given key from a file descriptor.
 * Expects the same format as the output from _export_fd().
 *
 * @return IOK or IERROR
 */
static int _import_fd(FILE *fd, exim_t* obj) {
  groupsig_signature_t *sig;
  cpy06_signature_t *cpy06_sig;
  struct pairing_s *pairing;
  uint8_t scheme;

  if(!fd || !obj) {
    LOG_EINVAL(&logger, __FILE__, "_import_fd", __LINE__,
           LOGERROR);
    return IERROR;
  }

  if(!(sig = cpy06_signature_init())) {
    return IERROR;
  }
  cpy06_sig = sig->sig;
  pairing = ((cpy06_sysenv_t *) sysenv->data)->pairing;


  /* First byte: scheme */
  if(fread(&scheme, sizeof(byte_t), 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "_import_fd", __LINE__,
          errno, LOGERROR);
    cpy06_signature_free(sig); sig = NULL;
    return IERROR;
  }

  /* Get T1 */
  element_init_G1(cpy06_sig->T1, pairing);
  if(pbcext_get_element_fd(cpy06_sig->T1, fd) == IERROR) {
    cpy06_signature_free(sig); sig = NULL;
    return IERROR;
  }

  /* Get T2 */
  element_init_G1(cpy06_sig->T2, pairing);
  if(pbcext_get_element_fd(cpy06_sig->T2, fd) == IERROR) {
    cpy06_signature_free(sig); sig = NULL;
    return IERROR;
  }

  /* Get T3 */
  element_init_G1(cpy06_sig->T3, pairing);
  if(pbcext_get_element_fd(cpy06_sig->T3, fd) == IERROR) {
    cpy06_signature_free(sig); sig = NULL;
    return IERROR;
  }

  /* Get T4 */
  element_init_G2(cpy06_sig->T4, pairing);
  if(pbcext_get_element_fd(cpy06_sig->T4, fd) == IERROR) {
    cpy06_signature_free(sig); sig = NULL;
    return IERROR;
  }

  /* Get T5 */
  element_init_GT(cpy06_sig->T5, pairing);
  if(pbcext_get_element_fd(cpy06_sig->T5, fd) == IERROR) {
    cpy06_signature_free(sig); sig = NULL;
    return IERROR;
  }

  /* Get c */
  element_init_Zr(cpy06_sig->c, pairing);
  if(pbcext_get_element_fd(cpy06_sig->c, fd) == IERROR) {
    cpy06_signature_free(sig); sig = NULL;
    return IERROR;
  }
  
  /* Get sr1 */
  element_init_Zr(cpy06_sig->sr1, pairing);
  if(pbcext_get_element_fd(cpy06_sig->sr1, fd) == IERROR) {
    cpy06_signature_free(sig); sig = NULL;
    return IERROR;
  }

  /* Get sr2 */
  element_init_Zr(cpy06_sig->sr2, pairing);
  if(pbcext_get_element_fd(cpy06_sig->sr2, fd) == IERROR) {
    cpy06_signature_free(sig); sig = NULL;
    return IERROR;
  }

  /* Get sd1 */
  element_init_Zr(cpy06_sig->sd1, pairing);
  if(pbcext_get_element_fd(cpy06_sig->sd1, fd) == IERROR) {
    cpy06_signature_free(sig); sig = NULL;
    return IERROR;
  }

  /* Get sd2 */
  element_init_Zr(cpy06_sig->sd2, pairing);
  if(pbcext_get_element_fd(cpy06_sig->sd2, fd) == IERROR) {
    cpy06_signature_free(sig); sig = NULL;
    return IERROR;
  }

  /* Get sx */
  element_init_Zr(cpy06_sig->sx, pairing);
  if(pbcext_get_element_fd(cpy06_sig->sx, fd) == IERROR) {
    cpy06_signature_free(sig); sig = NULL;
    return IERROR;
  }

  /* Get st */
  element_init_Zr(cpy06_sig->st, pairing);
  if(pbcext_get_element_fd(cpy06_sig->st, fd) == IERROR) {
    cpy06_signature_free(sig); sig = NULL;
    return IERROR;
  }

  obj->eximable = sig;
  return IOK;

}

/* Export/import handle definition */

static exim_handle_t _exim_h = {
  &_get_size_bytearray_null,
  &_export_fd,
  &_import_fd,
};

/* Public functions */
groupsig_signature_t* cpy06_signature_init() {

  groupsig_signature_t *sig;
  cpy06_signature_t *cpy06_sig;

  cpy06_sig = NULL;

  /* Initialize the signature contents */
  if(!(sig = (groupsig_signature_t *) mem_malloc(sizeof(groupsig_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "cpy06_signature_init", __LINE__, errno, 
		  LOGERROR);
  }

  if(!(cpy06_sig = (cpy06_signature_t *) mem_malloc(sizeof(cpy06_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "cpy06_signature_init", __LINE__, errno, 
		  LOGERROR);
    return NULL;
  }

  sig->scheme = GROUPSIG_CPY06_CODE;
  sig->sig = cpy06_sig;

  /* Since we use the PBC library, to initialize the signature fields, we need
     the pairing. Hence, they will be initialized during the sign procedure. */

  return sig;

}

int cpy06_signature_free(groupsig_signature_t *sig) {

  cpy06_signature_t *cpy06_sig;

  if(!sig || sig->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_signature_free", __LINE__,
		   "Nothing to free.", LOGWARN);    
    return IOK;
  }

  if(sig->sig) {
    cpy06_sig = sig->sig;
    element_clear(cpy06_sig->T1);
    element_clear(cpy06_sig->T2);
    element_clear(cpy06_sig->T3);
    element_clear(cpy06_sig->T4);
    element_clear(cpy06_sig->T5);
    element_clear(cpy06_sig->c);
    element_clear(cpy06_sig->sr1);
    element_clear(cpy06_sig->sr2);
    element_clear(cpy06_sig->sd1);
    element_clear(cpy06_sig->sd2);
    element_clear(cpy06_sig->sx);
    element_clear(cpy06_sig->st);
    mem_free(cpy06_sig); 
    cpy06_sig = NULL;
  }
  
  mem_free(sig);

  return IOK;

}

int cpy06_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src) {

  cpy06_signature_t *cpy06_dst, *cpy06_src;

  if(!dst || dst->scheme != GROUPSIG_CPY06_CODE ||
     !src || src->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_signature_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  cpy06_dst = dst->sig;
  cpy06_src = src->sig;

  /* Copy the elements */
  element_init_same_as(cpy06_dst->T1, cpy06_src->T1);
  element_set(cpy06_dst->T1, cpy06_src->T1);
  element_init_same_as(cpy06_dst->T2, cpy06_src->T2);
  element_set(cpy06_dst->T2, cpy06_src->T2);
  element_init_same_as(cpy06_dst->T3, cpy06_src->T3);
  element_set(cpy06_dst->T3, cpy06_src->T3);
  element_init_same_as(cpy06_dst->T4, cpy06_src->T4);
  element_set(cpy06_dst->T4, cpy06_src->T4);
  element_init_same_as(cpy06_dst->T5, cpy06_src->T5);
  element_set(cpy06_dst->T5, cpy06_src->T5);
  element_init_same_as(cpy06_dst->c, cpy06_src->c);
  element_set(cpy06_dst->c, cpy06_src->c);  
  element_init_same_as(cpy06_dst->sr1, cpy06_src->sr1);
  element_set(cpy06_dst->sr1, cpy06_src->sr1);
  element_init_same_as(cpy06_dst->sr2, cpy06_src->sr2);
  element_set(cpy06_dst->sr2, cpy06_src->sr2);
  element_init_same_as(cpy06_dst->sd1, cpy06_src->sd1);
  element_set(cpy06_dst->sd1, cpy06_src->sd1);
  element_init_same_as(cpy06_dst->sd2, cpy06_src->sd2);
  element_set(cpy06_dst->sd2, cpy06_src->sd2);
  element_init_same_as(cpy06_dst->sx, cpy06_src->sx);
  element_set(cpy06_dst->sx, cpy06_src->sx);
  element_init_same_as(cpy06_dst->st, cpy06_src->st);
  element_set(cpy06_dst->st, cpy06_src->st);

  return IOK;

}

char* cpy06_signature_to_string(groupsig_signature_t *sig) {

  char* b64;
  b64 = NULL;
  cpy06_signature_t* cpy06_sig;
  if(!sig || sig->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "signature_to_string", __LINE__, LOGERROR);
    return NULL;
  }
  
  cpy06_sig = (cpy06_signature_t*) sig->sig;
  b64 = _signature_to_string_b64(cpy06_sig);

  return b64;

}

int cpy06_signature_get_size_in_format(groupsig_signature_t *sig, groupsig_signature_format_t format) {

  if(!sig || sig->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_signature_get_size_in_format", __LINE__, LOGERROR);
    return -1;
  }

  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_signature_get_size_in_format", __LINE__,
  		   "The specified format is not supported.", LOGERROR);
    return -1;
  }

  exim_t wrap = {sig->sig, &_exim_h };
  return exim_get_size_in_format(&wrap, format);

}

int cpy06_signature_export(groupsig_signature_t *sig, groupsig_signature_format_t format, void *dst) { 

  if(!sig || sig->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_signature_export", __LINE__, LOGERROR);
    return IERROR;
  }

  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_signature_export", __LINE__,
  		   "The specified format is not supported.", LOGERROR);
    return IERROR;
  }

  exim_t wrap = {sig->sig, &_exim_h };
  return exim_export(&wrap, format, dst);

}

groupsig_signature_t* cpy06_signature_import(groupsig_signature_format_t format, void *source) {

  if(!source) {
    LOG_EINVAL(&logger, __FILE__, "signature_import", __LINE__, LOGERROR);
    return NULL;
  }

  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "signature_import", __LINE__,
  		   "The specified format is not supported.", LOGERROR);
    return NULL;
  }

  exim_t wrap = {NULL, &_exim_h };
  if(exim_import(format, source, &wrap) != IOK){
    return NULL;
  }

  return wrap.eximable;

}

/* signature.c ends here */
