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
#include "misc/misc.h"
#include "exim.h"
#include "kty04.h"
#include "groupsig/kty04/proof.h"

/* Private constants */
#define _INDEX_LENGTH 10

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

  for(i=0; i<KTY04_SUPPORTED_PROOF_FORMATS_N; i++) {
    if(KTY04_SUPPORTED_PROOF_FORMATS[i] == format) {
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
static int _get_size_bytearray_null(exim_t* obj){
  kty04_proof_t* proof;
  byte_t *bc=NULL, *bs=NULL;
  size_t sc, ss, sproof;

  if(!obj || !obj->eximable) {
    LOG_EINVAL(&logger, __FILE__, "_get_size_bytearray_null", __LINE__, LOGERROR);
    return -1;
  }
  proof = obj->eximable;

  /* Export the variables to binary data */
  if(!(bc = bigz_export(proof->c, &sc))) {
    return -1;
  }
  mem_free(bc); bc = NULL;

  if(!(bs = bigz_export(proof->s, &ss))) {
    return -1;
  }
  mem_free(bs); bs = NULL;
  // allow an extra byte for sign handling
  ss++;

  /* To separate the different values, and be able to parse them later, we use
     the 'syntax': "'c='<c>'s='<s>",
     where the values between '' are printed in ASCII, and the <x> are the binary
     data obtained above. Therefore, the total length of the proof will be
     2*2+sc+ss
     @todo although does not seem very probable, it is possible that the binary
     data of c, s, ... contains the ASCII codes of 'c=', 's=', etc.. This will
     obviously lead to program malfunction...
  */
  sproof = 2*sizeof(size_t)+sc+ss;

  return sproof;
}

/**
 * @fn static int _export_fd(exim_t* obj, FILE *fd)
 * @brief Writes a bytearray representation of the given exim object to a
 * file descriptor with format:
 *
 * 'c='<c>'s='<s>
 *
 * @param[in] key The key to export.
 * @param[in, out] fd An open filestream to write to.
 *
 * @return IOK or IERROR
 */
static int _export_fd(exim_t* obj, FILE *fd){
  kty04_proof_t* proof;
  byte_t *bc=NULL, *bs=NULL;
  size_t sc, ss;
  uint8_t count, neg;
  char sign;
  int rc;

  if(!obj | !obj->eximable) {
    LOG_EINVAL(&logger, __FILE__, "_export_fd", __LINE__,
           LOGERROR);
    return IERROR;
  }
  proof = obj->eximable;

  rc = IOK;

  if(bigz_dump_bigz_fd(proof->c, fd, 0) != IOK) GOTOENDRC(IERROR, _export_fd);
  if(bigz_dump_bigz_fd(proof->s, fd, 1) != IOK) GOTOENDRC(IERROR, _export_fd);

  _export_fd_end:

  if(bc) { free(bc); bc = NULL; }
  if(bs) { free(bs); bs = NULL; }

  return rc;

}

/**
 * @fn static int _import_fd(FILE *fd, exim_t* obj)
 * @brief Import a representation of the given key from a file descriptor.
 * Expects the same format as the output from _export_fd().
 *
 * @return IOK or IERROR
 */
static int _import_fd(FILE *fd, exim_t* obj){
  groupsig_proof_t *proof;
  kty04_proof_t *kty04_proof;
  bigz_t c, s;
  char sign;
  int rc;
  uint8_t count;


  if(!fd || !obj) {
    LOG_EINVAL(&logger, __FILE__, "_import_fd",
           __LINE__, LOGERROR);
    return IERROR;
  }

  if(bigz_get_bigz_fd(&c, fd, 0) != IOK) GOTOENDRC(IERROR, _import_fd);
  if(bigz_get_bigz_fd(&s, fd, 1) != IOK) GOTOENDRC(IERROR, _import_fd);


  proof=NULL; kty04_proof=NULL;
  rc = IOK;

  if(!(proof = kty04_proof_init()))
    GOTOENDRC(IERROR, _import_fd);

  kty04_proof = proof->proof;
  if(!(kty04_proof->c = bigz_init_set(c)))
    GOTOENDRC(IERROR, _import_fd);
  if(!(kty04_proof->s = bigz_init_set(s)))
    GOTOENDRC(IERROR, _import_fd);

  _import_fd_end:

  if(c) bigz_free(c);
  if(s) bigz_free(s);

  if(rc == IERROR) {
    if(proof) kty04_proof_free(proof);
  }

  obj->eximable = proof;
  return IOK;
}

/* Export/import handle definition */

static exim_handle_t _exim_h = {
  &_get_size_bytearray_null,
  &_export_fd,
  &_import_fd,
};

/* Public functions */
groupsig_proof_t* kty04_proof_init() {

  groupsig_proof_t *proof;
  kty04_proof_t *kty04_proof;

  proof = NULL; kty04_proof = NULL;

  /* Initialize the proof contents */
  if(!(proof = (groupsig_proof_t *) mem_malloc(sizeof(groupsig_proof_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_proof_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  if(!(kty04_proof = (kty04_proof_t *) mem_malloc(sizeof(kty04_proof_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_proof_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  kty04_proof->c = NULL; kty04_proof->s = NULL;
  proof->scheme = GROUPSIG_KTY04_CODE;
  proof->proof = kty04_proof;
  
  /* if(!(proof->c = bigz_init())) { */
  /*   free(proof); proof = NULL; */
  /*   return NULL; */
  /* } */

  /* if(!(proof->s = bigz_init())) { */
  /*   bigz_free(proof->c); */
  /*   free(proof); proof = NULL; */
  /*   return NULL; */
  /* } */

  return proof;

}

int kty04_proof_free(groupsig_proof_t *proof) {

  kty04_proof_t *kty04_proof;
  int rc;

  if(!proof || proof->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_proof_free", __LINE__,
		   "Nothing to free.", LOGWARN);    
    return IOK;
  }

  rc = IOK;
  kty04_proof = (kty04_proof_t *) proof->proof;

  rc += bigz_free(kty04_proof->c);
  rc += bigz_free(kty04_proof->s);
  mem_free(kty04_proof); kty04_proof = NULL;
  mem_free(proof);

  if(rc) rc = IERROR;

  return rc;

}

int kty04_proof_init_set_c(kty04_proof_t *proof, bigz_t c) {

  if(!proof || !c) {
    LOG_EINVAL(&logger, __FILE__, "kty04_proof_init_set_c", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(proof->c = bigz_init_set(c))) {
    return IERROR;
  }

  return IOK;

}

int kty04_proof_init_set_s(kty04_proof_t *proof, bigz_t s) {

  if(!proof || !s) {
    LOG_EINVAL(&logger, __FILE__, "kty04_proof_init_set_s", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(proof->s = bigz_init_set(s))) {
    return IERROR;
  }

  return IOK;

}

/* void* kty04_proof_copy(void *s) { */

/*   kty04_proof_t *cproof, *proof; */

/*   if(!s) { */
/*     LOG_EINVAL(&logger, __FILE__, "kty04_proof_copy", __LINE__, LOGERROR); */
/*     return NULL; */
/*   } */

/*   proof = (kty04_proof_t *) s; */
/*   if(proof->scheme != GROUPSIG_KTY04_CODE) { */
/*     LOG_EINVAL(&logger, __FILE__, "kty04_proof_copy", __LINE__, LOGERROR); */
/*     return NULL; */
/*   } */
/*   cproof = NULL; */

/*   /\* Initialize the proof contents *\/ */
/*   if(!(cproof = (kty04_proof_t *) malloc(sizeof(kty04_proof_t)))) { */
/*     LOG_ERRORCODE(&logger, __FILE__, "kty04_proof_copy", __LINE__, errno, LOGERROR); */
/*     return NULL; */
/*   } */

/*   cproof->c = NULL; cproof->s = NULL; */
  
/*   if(!(cproof->c = bigz_init_set(proof->c))) { */
/*     free(cproof); cproof = NULL; */
/*     return NULL; */
/*   } */

/*   if(!(cproof->s = bigz_init_set(proof->s))) { */
/*     bigz_free(cproof->c); */
/*     free(cproof); cproof = NULL; */
/*     return NULL; */
/*   } */

/*   return cproof; */

/* } */

char* kty04_proof_to_string(groupsig_proof_t *proof) {

  kty04_proof_t *kty04_proof;
  char *sc, *ss, *sproof;
  uint32_t size, offset;

  if(!proof || proof->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_proof_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  sc=NULL; ss=NULL; sproof=NULL;
  size = 2; 
  kty04_proof = (kty04_proof_t *) proof->proof;

  /* Get the strings of each of the fields */
  if(!(sc = bigz_get_str(10, kty04_proof->c))) return NULL;
  size += strlen(sc)+strlen("c: \n");

  if(!(ss = bigz_get_str(10, kty04_proof->s))) {
    free(sc); sc = NULL;
    return NULL;
  }
  size += strlen(ss)+strlen("s: \n");

  if(!(sproof = (char *) malloc(sizeof(char)*size))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_proof_to_string", __LINE__, errno, LOGERROR);
    free(sc); sc = NULL;
    free(ss); ss = NULL;
    return NULL;
  }

  memset(sproof, 0, sizeof(char)*size);

  /* Dump everything */
  sprintf(sproof, "c: %s\n", sc);
  offset = strlen(sc)+strlen("c: \n");
  sprintf(sproof, "s: %s\n", ss);
  offset = strlen(ss)+strlen("s: \n");

  sprintf(&sproof[offset], "\n");
  offset++;

  /* Free everything */
  if(sc) { free(sc); sc = NULL; }
  if(ss) { free(ss); ss = NULL; }
  
  return sproof;

}

int kty04_proof_export(groupsig_proof_t *proof, groupsig_proof_format_t format, void *dst) { 

  if(!proof || proof->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_proof_export", __LINE__, LOGERROR);
    return IERROR;
  }
  exim_t wrap = {proof->proof, &_exim_h };


  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_proof_export", __LINE__,
		   "The specified format is not supported.", LOGERROR);
    return IERROR;
  }

  return exim_export(&wrap, format, dst);

}

groupsig_proof_t* kty04_proof_import(groupsig_proof_format_t format, void *source) {

  if(!source) {
    LOG_EINVAL(&logger, __FILE__, "kty04_proof_import", __LINE__, LOGERROR);
    return NULL;
  }
  exim_t wrap = {NULL, &_exim_h };


  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_proof_import", __LINE__,
		   "The specified format is not supported.", LOGERROR);
    return NULL;
  }

  /** @todo For now, we just receive files. However, when included support for
      BBDD, etc., we'll have to deal with that here. In short, the idea is first
      to fetch the key from the specific source, returning an "object" of whatever
      type (e.g. a base64 string for base64 encoded keys in either a file or a BBDD)
	and then deal with that "objects" in each private key import function */

  if(exim_import(format, source, &wrap) == IOK){
    return wrap.eximable;
  }

  return NULL;

}

int kty04_proof_get_size_in_format(groupsig_proof_t *proof, groupsig_proof_format_t format) {

  if(!proof || proof->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_proof_get_size_in_format", __LINE__, LOGERROR);
    return -1;
  }
  exim_t wrap = {proof->proof, &_exim_h };


  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_proof_get_size_in_format", __LINE__,
		   "The specified format is not supported.", LOGERROR);
    return -1;
  }

  return exim_get_size_in_format(&wrap, format);

}

/* proof.c ends here */
