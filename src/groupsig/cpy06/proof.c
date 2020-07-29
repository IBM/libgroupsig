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
#include "groupsig/cpy06/proof.h"

/* Private functions */
/** 
 * @fn static int _is_supported_format(groupsig_proof_format_t format)
 * @brief Returns 1 if the specified format is supported by this scheme. 0 if not.
 *
 * @param[in] format The format to be "tested"
 * 
 * @return 1 if the specified format is supported, 0 if not.
 */
static int _is_supported_format(groupsig_proof_format_t format) {

  int i;

  for(i=0; i<CPY06_SUPPORTED_PROOF_FORMATS_N; i++) {
    if(CPY06_SUPPORTED_PROOF_FORMATS[i] == format) {
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
  cpy06_proof_t *proof = obj->eximable;

  // size = sizeof(code) + 2*size(element size data) + elements
  size = sizeof(byte_t) + 2*sizeof(int) +
      element_length_in_bytes(proof->c) + element_length_in_bytes(proof->s);

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
 * @param[in] obj The exim wrapped proof to export.
 * @param[in] fd The destination file descriptor. Must be big enough to store the result.
 *
 * @return IOK or IERROR:
 */
static int _export_fd(exim_t* obj, FILE *fd) {
  byte_t *bytes;
  uint64_t size, offset, written;
  cpy06_proof_t *proof;

  if(!obj || !obj->eximable || !fd) {
    LOG_EINVAL(&logger, __FILE__, "_export_fd", __LINE__,
           LOGERROR);
    return IERROR;
  }
  proof = obj->eximable;
  size = _get_size_bytearray_null(obj);//element_length_in_bytes(proof->c)+element_length_in_bytes(proof->s)+
    //sizeof(uint64_t)*2+1;

  if(!(bytes = (byte_t *) mem_malloc(sizeof(byte_t *)*size))) {
    return IERROR;
  }

  /* Dump GROUPSIG_CPY06_CODE */
  bytes[0] = GROUPSIG_CPY06_CODE;
  offset = 1;

  /* Dump T1 */
  if(pbcext_dump_element_bytes(&bytes[offset], &written, proof->c) == IERROR) {
    mem_free(bytes); bytes = NULL;
    return IERROR;
  }
  offset += written;

  /* Dump T2 */
  if(pbcext_dump_element_bytes(&bytes[offset], &written, proof->s) == IERROR) {
    mem_free(bytes); bytes = NULL;
    return IERROR;
  }
  offset += written;

  if(fwrite(bytes, offset, 1, fd) != 1){
    return IERROR;
  }

  mem_free(bytes); bytes = NULL;

  return IOK;

}

/**
 * @fn static int _import_fd(FILE *fd, exim_t* obj)
 * @brief Import a representation of the given key from a file descriptor.
 * Expects the same format as the output from _export_fd().
 *
 * @return IOK or IERROR
 */
static int _import_fd(FILE *fd, exim_t* obj) {
  groupsig_proof_t *proof;
  cpy06_proof_t *cpy06_proof;
  struct pairing_s *pairing;
  uint64_t size, offset, rd;
  int scheme;
  byte_t* buffer;

  if(!fd || !obj) {
    LOG_EINVAL(&logger, __FILE__, "_import_fd", __LINE__,
           LOGERROR);
    return IERROR;
  }

  if(!(proof = cpy06_proof_init())) {
    return IERROR;
  }
  size = misc_get_fd_size(fd);
  if(!(buffer = (byte_t*)mem_malloc(size))){
    return IERROR;
  }
  fread(buffer, size, 1, fd);
  cpy06_proof = proof->proof;
  pairing = ((cpy06_sysenv_t *) sysenv->data)->pairing;

  /* First byte: scheme */
  scheme = buffer[0];
  offset = 1;

  if(scheme != proof->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_import_fd", __LINE__,
              EDQUOT, "Unexpected proof scheme.", LOGERROR);
    cpy06_proof_free(proof); proof = NULL;
    return IERROR;
  }

  /* Get Zr */
  element_init_Zr(cpy06_proof->c, pairing);
  if(pbcext_get_element_bytes(cpy06_proof->c, &rd, &buffer[offset]) == IERROR) {
    cpy06_proof_free(proof); proof = NULL;
    return IERROR;
  }
  offset += rd;

  /* Get s */
  element_init_Zr(cpy06_proof->s, pairing);
  if(pbcext_get_element_bytes(cpy06_proof->s, &rd, &buffer[offset]) == IERROR) {
    cpy06_proof_free(proof); proof = NULL;
    return IERROR;
  }
  offset += rd;

  obj->eximable = proof;
  return IOK;
}

/* Export/import handle definition */

static exim_handle_t _exim_h = {
  &_get_size_bytearray_null,
  &_export_fd,
  &_import_fd,
};

groupsig_proof_t* cpy06_proof_init() {

  groupsig_proof_t *proof;

  if(!(proof = (groupsig_proof_t *) mem_malloc(sizeof(groupsig_proof_t)))) {
    return NULL;
  }

  proof->scheme = GROUPSIG_CPY06_CODE;
  if(!(proof->proof = (cpy06_proof_t *) mem_malloc(sizeof(cpy06_proof_t)))) {
    mem_free(proof); proof = NULL;
    return NULL;
  }

  return proof;
}

int cpy06_proof_free(groupsig_proof_t *proof) {

  if(!proof) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_proof_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IERROR;
  }

  if(proof->proof) {
    element_clear(((cpy06_proof_t *) proof->proof)->c);
    element_clear(((cpy06_proof_t *) proof->proof)->s);
    mem_free(proof->proof); proof->proof = NULL;
  }

  mem_free(proof);

  return IOK;

}

/* int cpy06_proof_init_set_c(cpy06_proof_t *proof, bigz_t c) { */

/*   if(!proof || !c) { */
/*     LOG_EINVAL(&logger, __FILE__, "cpy06_proof_init_set_c", __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   if(!(proof->c = bigz_init_set(c))) { */
/*     return IERROR; */
/*   } */

/*   return IOK; */

/* } */

/* int cpy06_proof_init_set_s(cpy06_proof_t *proof, bigz_t s) { */

/*   if(!proof || !s) { */
/*     LOG_EINVAL(&logger, __FILE__, "cpy06_proof_init_set_s", __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   if(!(proof->s = bigz_init_set(s))) { */
/*     return IERROR; */
/*   } */

/*   return IOK; */

/* } */

char* cpy06_proof_to_string(groupsig_proof_t *proof) {

  if(!proof || proof->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_proof_to_string", __LINE__, LOGERROR);
    return NULL;
  }
  
  return NULL;

}

int cpy06_proof_export(groupsig_proof_t *proof, groupsig_proof_format_t format, void *dst) { 

  cpy06_proof_t *cpy06_proof;

  if(!proof || proof->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_proof_export", __LINE__, LOGERROR);
    return IERROR;
  }

  cpy06_proof = (cpy06_proof_t *) proof->proof;

  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_proof_export", __LINE__,
  		   "The specified format is not supported.", LOGERROR);
    return IERROR;
  }

  exim_t wrap = {cpy06_proof, &_exim_h };
  return exim_export(&wrap, format, dst);

}

groupsig_proof_t* cpy06_proof_import(groupsig_proof_format_t format, void *source) {

  if(!source) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_proof_import", __LINE__, LOGERROR);
    return NULL;
  }

  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_proof_import", __LINE__,
  		   "The specified format is not supported.", LOGERROR);
    return NULL;
  }

  exim_t wrap = {NULL, &_exim_h };
  if(exim_import(format, source, &wrap) != IOK){
    return NULL;
  }

  return wrap.eximable;
  
}

int cpy06_proof_get_size_in_format(groupsig_proof_t *proof, groupsig_proof_format_t format) {

  if(!proof || proof->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_proof_get_size_in_format", __LINE__, LOGERROR);
    return -1;
  }

  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_proof_get_size_in_format", __LINE__,
  		   "The specified format is not supported.", LOGERROR);
    return -1;
  }

  exim_t wrap = {proof->proof, &_exim_h };
  return exim_get_size_in_format(&wrap, format);

}

/* proof.c ends here */
