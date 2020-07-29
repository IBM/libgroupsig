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
#include "groupsig/kty04/signature.h"

/* Private constants */
#define _INDEX_LENGTH 10

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

  for(i=0; i<KTY04_SUPPORTED_SIG_FORMATS_N; i++) {
    if(KTY04_SUPPORTED_SIG_FORMATS[i] == format) {
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
  kty04_signature_t *sig;
  byte_t *bytes;
  size_t sc, sA, ssw;
  int ssig, rc, i;

  if(!obj || !obj->eximable) {
    LOG_EINVAL(&logger, __FILE__, "_signature_get_size_string_null_b64", __LINE__, LOGERROR);
    return -1;
  }
  sig = obj->eximable;

  ssig = 0; rc = IOK;

  /* Export the variables to binary data */
  if(!(bytes = bigz_export(sig->c, &sc)))
    GOTOENDRC(IERROR, _get_size_bytearray_null);
  mem_free(bytes); bytes = NULL;
  ssig += sc;

  /* Precalculate the size of all the A's */
  for(i=0; i < sig->m; i++) {
    if(!(bytes = bigz_export(sig->A[i], &sA))) {
      GOTOENDRC(IERROR, _get_size_bytearray_null);
    }
    mem_free(bytes); bytes = NULL;
    ssig += sA;
  }

  /* mem_free(bytes); bytes = NULL; */

  /* Precalculate the size of all the sw's */
  for(i=0; i < sig->r; i++) {
    if(!(bytes = bigz_export(sig->sw[i], &ssw))) {
      GOTOENDRC(IERROR, _get_size_bytearray_null);
    }
    mem_free(bytes); bytes = NULL;
    // Allow an extra byte for sign handling
    ssig += ssw + 1;
  }

  /* Add the sizes of the "meta information":
   * sizeof(size sc) + sizeof(m, z, r) + sizeof(size (M's + R's))
   */
  ssig += sizeof(size_t) + 3*sizeof(uint32_t) + sizeof(size_t)*(sig->m + sig->r);

  _get_size_bytearray_null_end:

  if(bytes) { mem_free(bytes); bytes = NULL; }

  if(rc == IERROR) return -1;

  return ssig;
}

/**
 * @fn static int _export_fd(exim_t* obj, FILE *fd)
 * @brief Writes a bytearray representation of the given exim object to a
 * file descriptor with format:
 *
 * | size c | c | m | z | r | size A[1] | A[1] | ... | size A[m] | A[m] |
 * | size sw[1] | sw[1] | ... | size sw[r] | sw[r] |
 * 'c='<c>'m='<m>'z='<z>'r='<r>'A='<A[1]>...'A='<A[m]>'s='<sw[1]>...'s='<sw[r]>
 *
 * @param[in] key The key to export.
 * @param[in, out] fd An open filestream to write to.
 *
 * @return IOK or IERROR
 */
static int _export_fd(exim_t* obj, FILE *fd){
  kty04_signature_t *sig;
  uint32_t i;
  uint8_t count, neg;
  char sign;
  int rc;

  if(!obj || !obj->eximable || !fd) {
    LOG_EINVAL(&logger, __FILE__, "_export_fd", __LINE__, LOGERROR);
    return IERROR;
  }
  sig = obj->eximable;

  rc = IOK;

  if(bigz_dump_bigz_fd(sig->c, fd, 0) != IOK) GOTOENDRC(IERROR, _export_fd);

  count = 0;
  /* Put the m */
  count += fwrite(&sig->m, sizeof(uint32_t), 1, fd);
  /* Put the z */
  count += fwrite(&sig->z, sizeof(uint32_t), 1, fd);
  /* Put the r */
  count += fwrite(&sig->r, sizeof(uint32_t), 1, fd);
  if(count != 3) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_export_fd", __LINE__,
              EDQUOT, "Export failure.", LOGERROR);
    GOTOENDRC(IERROR, _export_fd);
  }

  /* Put the A's */
  for(i=0; i < sig->m; i++) {
    if(bigz_dump_bigz_fd(sig->A[i], fd, 0) != IOK) GOTOENDRC(IERROR, _export_fd);
  }

  /* Put the sw's */
  for(i=0; i < sig->r; i++) {
    if(bigz_dump_bigz_fd(sig->sw[i], fd, 1) != IOK) GOTOENDRC(IERROR, _export_fd);
  }


  /*int u = misc_get_fd_size(fd);
  int v = _get_size_bytearray_null(obj);
  if(misc_get_fd_size(fd) < _get_size_bytearray_null(obj)){
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_export_fd", __LINE__,
                  EDQUOT, "Export failure.", LOGERROR);
    GOTOENDRC(IERROR, _export_fd);
  }*/

  _export_fd_end:

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
  groupsig_signature_t *sig;
  kty04_signature_t *kty04_sig;
  bigz_t c, *A, *sw;
  uint32_t m, z, r;
  char sign;
  int rc;
  int i, count;

  if(!fd || !obj) {
    LOG_EINVAL(&logger, __FILE__, "_import_fd", __LINE__,
           LOGERROR);
    return IERROR;
  }

  sig = NULL;
  kty04_sig=NULL; c=NULL; A=NULL; sw=NULL;
  rc = IOK;

  /* Read items there are only one of */

  if(bigz_get_bigz_fd(&c, fd, 0) != IOK) GOTOENDRC(IERROR, _import_fd);

  count = 0;
  count += fread(&m, sizeof(uint32_t), 1, fd);
  count += fread(&z, sizeof(uint32_t), 1, fd);
  count += fread(&r, sizeof(uint32_t), 1, fd);
  if(count != 3) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_import_fd", __LINE__,
              EDQUOT, "Import failure.", LOGERROR);
    GOTOENDRC(IERROR, _import_fd);
  }

  /* Read the data that are arrays */
  // Set up an array of bigz As
  if(!(A = (bigz_t *) mem_malloc(sizeof(bigz_t)*m))) {
    LOG_ERRORCODE(&logger, __FILE__, "_import_fd", __LINE__,
          errno, LOGERROR);
    GOTOENDRC(IERROR, _import_fd);
  }

  // Read in the As
  for(i=0; i < m; i++) {
    if(bigz_get_bigz_fd(&A[i], fd, 0) != IOK) GOTOENDRC(IERROR, _import_fd);
  }

  // Set up an array to hold bigz SWs
  if(!(sw = (bigz_t *) mem_malloc(sizeof(bigz_t)*r))) {
    LOG_ERRORCODE(&logger, __FILE__, "_import_fd", __LINE__,
          errno, LOGERROR);
    GOTOENDRC(IERROR, _import_fd);
  }

  for(i=0; i < r; i++) {
    if(bigz_get_bigz_fd(&sw[i], fd, 1) != IOK) GOTOENDRC(IERROR, _import_fd);
  }

  if(!(sig = kty04_signature_init())) GOTOENDRC(IERROR, _import_fd);

  kty04_sig = sig->sig;
  kty04_sig->m = m;
  kty04_sig->z = z;
  kty04_sig->r = r;
  if(bigz_set(kty04_sig->c, c) == IERROR) GOTOENDRC(IERROR, _import_fd);

  for(i=0; i < m; i++) {
    if(bigz_set(kty04_sig->A[i], A[i]) == IERROR)
      GOTOENDRC(IERROR, _import_fd);
  }

  for(i=0; i < r; i++) {
    if(bigz_set(kty04_sig->sw[i], sw[i]) == IERROR)
      GOTOENDRC(IERROR, _import_fd);
  }

 _import_fd_end:

  if(c) bigz_free(c);

  if (A) {
    for (i = 0; i < m; i++) {
      if (A[i])
        bigz_free(A[i]);
    }
    mem_free(A);
    A = NULL;
  }

  if (sw) {
    for (i = 0; i < r; i++) {
      if (sw[i])
        bigz_free(sw[i]);
    }
    mem_free(sw);
    sw = NULL;
  }

  if(rc == IERROR) {
    if(sig) kty04_signature_free(sig);
  }

  obj->eximable = sig;
  return rc;

}

/* Export/import handle definition */

static exim_handle_t _exim_h = {
  &_get_size_bytearray_null,
  &_export_fd,
  &_import_fd,
};

/* Public functions */
groupsig_signature_t* kty04_signature_init() {

  groupsig_signature_t *sig;
  kty04_signature_t *kty04_sig;
  uint32_t i;
  int rc;

  kty04_sig = NULL;
  rc = IOK;

  /* Initialize the signature contents */
  if(!(sig = (groupsig_signature_t *) mem_malloc(sizeof(groupsig_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_signature_init", __LINE__, errno, 
		  LOGERROR);
  }

  if(!(kty04_sig = (kty04_signature_t *) mem_malloc(sizeof(kty04_signature_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_signature_init", __LINE__, errno, 
		  LOGERROR);
    return NULL;
  }

  kty04_sig->c = NULL; kty04_sig->A = NULL; kty04_sig->sw = NULL;
  
  if(!(kty04_sig->c = bigz_init())) GOTOENDRC(IERROR, kty04_signature_init);

  /* Initialize the A's */
  kty04_sig->m = KTY04_SIGNATURE_M;
  if(!(kty04_sig->A = (bigz_t *) malloc(sizeof(bigz_t)*kty04_sig->m))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_signature_init", __LINE__, errno, LOGERROR);
    GOTOENDRC(IERROR, kty04_signature_init);
  }
  memset(kty04_sig->A, 0, sizeof(bigz_t)*kty04_sig->m);

  for(i=0; i<kty04_sig->m; i++) {
    if(!(kty04_sig->A[i] = bigz_init())) GOTOENDRC(IERROR, kty04_signature_init);
  }

  /* Set the number of relations to the default */
  kty04_sig->z = KTY04_SIGNATURE_Z;

  /* Initialize the sw's */
  kty04_sig->r = KTY04_SIGNATURE_R;
  if(!(kty04_sig->sw = (bigz_t *) malloc(sizeof(bigz_t)*kty04_sig->r))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_signature_init", __LINE__, errno, LOGERROR);
    GOTOENDRC(IERROR, kty04_signature_init);
  }
  memset(kty04_sig->sw, 0, sizeof(bigz_t)*kty04_sig->r);

  for(i=0; i<kty04_sig->r; i++) {
    if(!(kty04_sig->sw[i] = bigz_init())) GOTOENDRC(IERROR, kty04_signature_init);
  }

  sig->scheme = GROUPSIG_KTY04_CODE;
  sig->sig = kty04_sig;

 kty04_signature_init_end:

  if(rc == IERROR) {
    if(kty04_sig->c) bigz_free(kty04_sig->c);
    if(kty04_sig->A) for(i=0; i<kty04_sig->m; i++) bigz_free(kty04_sig->A[i]);
    if(kty04_sig->sw) for(i=0; i<kty04_sig->r; i++) bigz_free(kty04_sig->sw[i]);
    if(kty04_sig) { free(kty04_sig); kty04_sig = NULL; }
    if(sig) { free(sig); sig = NULL; }
  }

  return sig;

}

int kty04_signature_free(groupsig_signature_t *sig) {

  kty04_signature_t *kty04_sig;
  uint32_t i;
  int rc;

  if(!sig || sig->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_signature_free", __LINE__,
		   "Nothing to free.", LOGWARN);    
    return IOK;
  }

  rc = IOK;
  kty04_sig = (kty04_signature_t *) sig->sig;

  /* Free the c */  
  rc += bigz_free(kty04_sig->c);

  /* Free the A's */
  if(kty04_sig->A) {
    for(i=0; i<kty04_sig->m; i++) {
      rc += bigz_free(kty04_sig->A[i]);
    }
    free(kty04_sig->A); kty04_sig->A = NULL;
  }

  /* Free the sw's */
  if(kty04_sig->sw) {
    for(i=0; i<kty04_sig->r; i++) {
      rc += bigz_free(kty04_sig->sw[i]);
    }
    free(kty04_sig->sw); kty04_sig->sw = NULL;
  }

  free(kty04_sig); kty04_sig = NULL;
  free(sig);

  if(rc) return IERROR;
  return IOK;

}

int kty04_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src) {

  kty04_signature_t *kty04_dst, *kty04_src;
  uint32_t i;

  if(!dst || dst->scheme != GROUPSIG_KTY04_CODE ||
     !src || src->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_signature_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  kty04_src = (kty04_signature_t *) src->sig;
  kty04_dst = (kty04_signature_t *) dst->sig;

  /* Initialize the signature contents */
  if(bigz_set(kty04_dst->c, kty04_src->c) == IERROR)
    return IERROR;

  /* Initialize the A's */
  kty04_dst->m = kty04_src->m;
  for(i=0; i<kty04_dst->m; i++) {
    if(bigz_set(kty04_dst->A[i], kty04_src->A[i]) == IERROR) 
      return IERROR;
  }

  /* Set the number of relations to the default */
  kty04_dst->z = kty04_src->z;

  /* Initialize the sw's */
  kty04_dst->r = kty04_src->r;
  for(i=0; i<kty04_dst->r; i++) {
    if(bigz_set(kty04_dst->sw[i], kty04_src->sw[i]) == IERROR) 
      return IERROR;
  }

  return IOK;

}

char* kty04_signature_to_string(groupsig_signature_t *sig) {

  kty04_signature_t *kty04_sig;
  char *sc, **ssw, **sA, *ssig;
  uint32_t i, size, offset;
  int rc;

  if(!sig || sig->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "signature_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  sc=NULL; ssw=NULL; sA=NULL; ssig=NULL;
  size = 0; 
  rc = IOK;
  kty04_sig = (kty04_signature_t *) sig->sig;

  /* Get the strings of each of the fields */
  if(!(sc = bigz_get_str(10, kty04_sig->c))) GOTOENDRC(IERROR, kty04_signature_to_string);
  size += strlen(sc)+strlen("c: \n");

  if(!(sA = (char **) malloc(sizeof(char *)*kty04_sig->m))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_signature_to_string", __LINE__, errno, LOGERROR);
    GOTOENDRC(IERROR, kty04_signature_to_string);
  }
  memset(sA, 0, sizeof(char *)*kty04_sig->m);

  /* We give the indexes an arbitrary size of 10 decimal digits (chars). If they 
     are bigger, they will be truncated. 10 seems much more than enough and  
     using a fixed size makes things much easier... */
  for(i=0; i<kty04_sig->m; i++) {
    if(!(sA[i] = bigz_get_str(10, kty04_sig->A[i]))) return NULL;
    size += strlen(sA[i])+strlen("A[]: \n")+_INDEX_LENGTH;
  }
  size += 1;
 
  if(!(ssw = (char **) malloc(sizeof(char *)*kty04_sig->r))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_signature_to_string", __LINE__, errno, LOGERROR);
    GOTOENDRC(IERROR, kty04_signature_to_string);
  }
  memset(ssw, 0, sizeof(char *)*kty04_sig->r);

  for(i=0; i<kty04_sig->r; i++) {
    if(!(ssw[i] = bigz_get_str(10, kty04_sig->sw[i]))) return NULL;
    size += strlen(ssw[i])+strlen("s[]: \n")+_INDEX_LENGTH;
  }
  size += 1;

  if(!(ssig = (char *) malloc(sizeof(char)*size))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_signature_to_string", __LINE__, errno, LOGERROR);
    GOTOENDRC(IERROR, kty04_signature_to_string);
  }
  memset(ssig, 0, sizeof(char)*size);

  /* Dump everything */
  sprintf(ssig, "c: %s\n", sc);
  offset = strlen(sc)+strlen("c: \n");

  for(i=0; i<kty04_sig->m; i++) {
    sprintf(&ssig[offset], "A[%u]: %s\n", i, sA[i]);
    offset += strlen(sA[i])+strlen("A[ ]: \n");
  }
  sprintf(&ssig[offset], "\n");
  offset++;

  for(i=0; i<kty04_sig->r; i++) {
    sprintf(&ssig[offset], "s[%u]: %s\n", i, ssw[i]);
    offset += strlen(ssw[i])+strlen("s[ ]: \n");
  }
  sprintf(&ssig[offset], "\n");
  offset++;

 kty04_signature_to_string_end:

  /* Free everything */
  if(sc) { free(sc); sc = NULL; }

  if(sA) {
    for(i=0; i<kty04_sig->m; i++) {
      free(sA[i]); sA[i] = NULL;
    }
    free(sA); sA = NULL;
  }

  if(ssw) {
    for(i=0; i<kty04_sig->r; i++) {
      free(ssw[i]); ssw[i] = NULL;
    }
    free(ssw); ssw = NULL;
  }
  
  if(rc == IERROR) {
    if(ssig) { free(ssig); ssig = NULL; }
  }
  
  return ssig;

}

int kty04_signature_get_size_in_format(groupsig_signature_t *sig, groupsig_signature_format_t format) {

  if(!sig || sig->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_signature_get_size_in_format", __LINE__, LOGERROR);
    return -1;
  }
  exim_t wrap = {sig->sig, &_exim_h };


  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_signature_get_size_in_format", __LINE__,
           "The specified format is not supported.", LOGERROR);
    return -1;
  }

  return exim_get_size_in_format(&wrap, format);

}

int kty04_signature_export(groupsig_signature_t *sig, groupsig_signature_format_t format, void *dst) { 

  if(!sig || sig->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_signature_export", __LINE__, LOGERROR);
    return IERROR;
  }
  exim_t wrap = {sig->sig, &_exim_h };

  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_signature_export", __LINE__,
		   "The specified format is not supported.", LOGERROR);
    return IERROR;
  }

  return exim_export(&wrap, format, dst);

}

groupsig_signature_t* kty04_signature_import(groupsig_signature_format_t format, void *source) {

  if(!source) {
    LOG_EINVAL(&logger, __FILE__, "kty04_signature_import", __LINE__, LOGERROR);
    return NULL;
  }
  exim_t wrap = {NULL, &_exim_h };


  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_signature_import", __LINE__,
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

/* signature.c ends here */
