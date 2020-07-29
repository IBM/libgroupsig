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
#include <fcntl.h>
#include <math.h>

#include "kty04.h"
#include "groupsig/kty04/mem_key.h"
#include "wrappers/base64.h"
#include "misc/misc.h"
#include "exim.h"
#include "sys/mem.h"

/* Private functions */

/** 
 * @fn static int _is_supported_format(groupsig_key_format_t format)
 * @brief Returns 1 if the specified format is supported by this scheme. 0 if not.
 *
 * @param[in] format The format to be "tested"
 * 
 * @return 1 if the specified format is supported, 0 if not.
 */
static int _is_supported_format(groupsig_key_format_t format) {

  int i;

  for(i=0; i<KTY04_SUPPORTED_KEY_FORMATS_N; i++) {
    if(KTY04_SUPPORTED_KEY_FORMATS[i] == format) {
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
  kty04_mem_key_t *mkey;
  size_t size;
  byte_t *bA=NULL, *bC=NULL, *bx=NULL, *bxx=NULL, *be=NULL;
  size_t sA, sC, sx, sxx, se;

  sA = 0; sC = 0; sx = 0; sxx = 0; se = 0;
  mkey = (kty04_mem_key_t *) obj->eximable;

  /* Export the variables to binary data */
  errno = 0;
  if(mkey->A && bigz_cmp_ui(mkey->A, 0)) {
    if(errno || !(bA = bigz_export(mkey->A, &sA))) {
      return -1;
    }
  }

  errno = 0;
  if(mkey->C && bigz_cmp_ui(mkey->C, 0)) {
    if(errno || !(bC = bigz_export(mkey->C, &sC))) {
      return -1;
    }
  }

  errno = 0;
  if(mkey->x && bigz_cmp_ui(mkey->x, 0)) {
    if(errno || !(bx = bigz_export(mkey->x, &sx))) {
      return -1;
    }
  }

  errno = 0;
  if(mkey->xx && bigz_cmp_ui(mkey->xx, 0)) {
    if(errno || !(bxx = bigz_export(mkey->xx, &sxx))) {
      return -1;
    }
  }

  errno = 0;
  if(mkey->e && bigz_cmp_ui(mkey->e, 0)) {
    if(errno || !(be = bigz_export(mkey->e, &se))) {
      return -1;
    }
  }

  /* To separate the different values, and be able to parse them later, we use
     the 'syntax': "'A='<A>'C='<C>'x='<x>'xx='<xx>'e='<e>",
     where the values between '' are printed in ASCII, and the <x> are the binary
     data obtained above. Therefore, the total length of the member key will be
     5*2+sA+sC+sx+sxx+se.
     @todo although does not seem very probable, it is possible that the binary
     data of n, e, ... contains the ASCII codes of 'n=', 'e=', etc.. This will
     obviously lead to program malfunction...
  */

  /* We only need their sizes */
  mem_free(bA); bA = NULL;
  mem_free(bC); bC = NULL;
  mem_free(bx); bx = NULL;
  mem_free(bxx); bxx = NULL;
  mem_free(be); be = NULL;


  size = 5*sizeof(size_t)+sA+sC+sx+sxx+se;
  return size;
}

/**
 * @fn static int _export_fd(exim_t* obj, FILE *fd)
 * @brief Writes a bytearray representation of the given exim object to a
 * file descriptor with format:
 *
 *  | size A | A | size C | C | size x | x | size xx | xx | size e | e |
 * 'A='<A>'C='<C>'x='<x>'xx='<xx>'e='<e>
 *
 * @param[in] key The key to export.
 * @param[in, out] fd An open filestream to write to.
 *
 * @return IOK or IERROR
 */
static int _export_fd(exim_t* obj, FILE *fd) {
  kty04_mem_key_t *mkey;
  int rc;

  if(!obj | !obj->eximable | !fd) {
    LOG_EINVAL(&logger, __FILE__, "_export_fd", __LINE__, LOGERROR);
    return IERROR;
  }

  kty04_mem_key_t *key = obj->eximable;

  mkey = (kty04_mem_key_t *) key; rc = IOK;

  if(bigz_dump_bigz_fd(mkey->A, fd, 0) != IOK) GOTOENDRC(IERROR, _export_fd);
  if(bigz_dump_bigz_fd(mkey->C, fd, 0) != IOK) GOTOENDRC(IERROR, _export_fd);
  if(bigz_dump_bigz_fd(mkey->x, fd, 0) != IOK) GOTOENDRC(IERROR, _export_fd);
  if(bigz_dump_bigz_fd(mkey->xx, fd, 0) != IOK) GOTOENDRC(IERROR, _export_fd);
  if(bigz_dump_bigz_fd(mkey->e, fd, 0) != IOK) GOTOENDRC(IERROR, _export_fd);

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
  bigz_t A, C, x, xx, e;
  groupsig_key_t *key;
  kty04_mem_key_t *kty04_key;
  int rc;

  if(!fd || !obj) {
    LOG_EINVAL(&logger, __FILE__, "_import_fd", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;

  if(bigz_get_bigz_fd(&A, fd, 0) != IOK) GOTOENDRC(IERROR, _import_fd);
  if(bigz_get_bigz_fd(&C, fd, 0) != IOK) GOTOENDRC(IERROR, _import_fd);
  if(bigz_get_bigz_fd(&x, fd, 0) != IOK) GOTOENDRC(IERROR, _import_fd);
  if(bigz_get_bigz_fd(&xx, fd, 0) != IOK) GOTOENDRC(IERROR, _import_fd);
  if(bigz_get_bigz_fd(&e, fd, 0) != IOK) GOTOENDRC(IERROR, _import_fd);


  if(!(key = kty04_mem_key_init())) GOTOENDRC(IERROR, _import_fd);

  kty04_key = key->key;

  if(bigz_set(kty04_key->A, A) == IERROR) GOTOENDRC(IERROR, _import_fd);
  if(bigz_set(kty04_key->C, C) == IERROR) GOTOENDRC(IERROR, _import_fd);
  if(bigz_set(kty04_key->x, x) == IERROR) GOTOENDRC(IERROR, _import_fd);
  if(bigz_set(kty04_key->xx, xx) == IERROR) GOTOENDRC(IERROR, _import_fd);
  if(bigz_set(kty04_key->e, e) == IERROR) rc = IERROR;

  _import_fd_end:

  /* If any of the following variables is NULL it means that
     an error has occured */
  if(A) bigz_free(A);
  if(C) bigz_free(C);
  if(x) bigz_free(x);
  if(xx) bigz_free(xx);
  if(e) bigz_free(e);

  if(rc == IERROR) {
    if(key) kty04_mem_key_free(key);
    return IERROR;
  }
  obj->eximable = key;
  return IOK;
}

/* Export/import handle definition */

static exim_handle_t _exim_h = {
  &_get_size_bytearray_null,
  &_export_fd,
  &_import_fd,
};

/* Public functions */

groupsig_key_t* kty04_mem_key_init() {

  kty04_mem_key_t *kty04_key;
  groupsig_key_t *key;

  if(!(key = (groupsig_key_t *) malloc(sizeof(groupsig_key_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mem_key_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  if(!(kty04_key = (kty04_mem_key_t *) malloc(sizeof(kty04_mem_key_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mem_key_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  kty04_key->A = NULL; kty04_key->C = NULL; kty04_key->x = NULL; 
  kty04_key->xx = NULL, kty04_key->e = NULL;

  if(!(kty04_key->A = bigz_init())) goto init_error;
  if(!(kty04_key->C = bigz_init())) goto init_error;
  if(!(kty04_key->x = bigz_init())) goto init_error;
  if(!(kty04_key->xx = bigz_init())) goto init_error;
  if(!(kty04_key->e = bigz_init())) goto init_error;

  key->scheme = GROUPSIG_KTY04_CODE;
  key->key = kty04_key;

  return key;

 init_error:
  
  if(kty04_key->A) bigz_free(kty04_key->A);
  if(kty04_key->C) bigz_free(kty04_key->C);
  if(kty04_key->x) bigz_free(kty04_key->x);
  if(kty04_key->xx) bigz_free(kty04_key->xx);
  if(kty04_key->e) bigz_free(kty04_key->e);
  if(kty04_key) { free(kty04_key); kty04_key = NULL; }
  if(key) { free(key); key = NULL; }
  
  return NULL;

}

int kty04_mem_key_free(groupsig_key_t *key) {

  kty04_mem_key_t *kty04_key;
  int rc;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_mem_key_free", __LINE__, 
       "Nothing to free.", LOGERROR);
    return IERROR;
  }

  rc = IOK;
  kty04_key = (kty04_mem_key_t *) key->key;
  
  rc += bigz_free(kty04_key->A);
  rc += bigz_free(kty04_key->C);
  rc += bigz_free(kty04_key->x);
  rc += bigz_free(kty04_key->xx);
  rc += bigz_free(kty04_key->e);
  
  free(kty04_key); kty04_key = NULL;
  free(key);

  if(rc != IOK) rc = IERROR;
  
  return rc;

}

int kty04_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  kty04_mem_key_t *dkey, *skey;

  if(!dst  || dst->scheme != GROUPSIG_KTY04_CODE || 
     !src  || src->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  dkey = (kty04_mem_key_t *) dst->key;
  skey = (kty04_mem_key_t *) src->key;
  
  if(bigz_set(dkey->A, skey->A) == IERROR)
    return IERROR;

  if(bigz_set(dkey->C, skey->C) == IERROR)
    return IERROR;

  if(bigz_set(dkey->x, skey->x) == IERROR)
    return IERROR;
  
  if(bigz_set(dkey->xx, skey->xx) == IERROR)
    return IERROR;
  
  if(bigz_set(dkey->e, skey->e) == IERROR)
    return IERROR;

  dst->scheme = GROUPSIG_KTY04_CODE;
  dst->key = dkey;

  return IOK;

}

int kty04_mem_key_get_size_in_format(groupsig_key_t *key, groupsig_key_format_t format) {

  if(!key || key->scheme != GROUPSIG_KTY04_CODE ||
     !_is_supported_format(format)) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_get_size_in_format", __LINE__, LOGERROR);
    return -1;
  }
  exim_t wrap = {key->key, &_exim_h };


  return exim_get_size_in_format(&wrap, format);

}

groupsig_key_t* kty04_mem_key_get_prv(groupsig_key_t *key) {

  groupsig_key_t *prv_key;
  kty04_mem_key_t *kty04_prv_key, *kty04_key;
  
  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_get_prv", __LINE__, LOGERROR);
    return NULL;
  }

  kty04_key = (kty04_mem_key_t *) key->key;

  if(!(prv_key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mem_key_get_prv", __LINE__, errno, LOGERROR);
    return NULL;
  }
  
  /* The private part of the member key is the x' (xx) value */
  if(!(kty04_prv_key = (kty04_mem_key_t *) mem_malloc(sizeof(kty04_mem_key_t)))) {
    mem_free(prv_key); prv_key = NULL;
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mem_key_get_prv", __LINE__, errno, LOGERROR);
    return NULL;
  }

  /* Initialize and set the xx field */
  if(!(kty04_prv_key->xx = bigz_init_set(kty04_key->xx))) {
    mem_free(prv_key); prv_key = NULL;
    free(kty04_prv_key); kty04_prv_key = NULL;
    return NULL;
  }

  /* Set the remaining elements to NULL */
  kty04_prv_key->A = NULL;
  kty04_prv_key->C = NULL;
  kty04_prv_key->x = NULL;
  kty04_prv_key->e = NULL;

  prv_key->scheme = GROUPSIG_KTY04_CODE;
  prv_key->key = kty04_prv_key;
  
  return prv_key;

}

groupsig_key_t* kty04_mem_key_get_pub(groupsig_key_t *key) {

  groupsig_key_t *pub_key;
  kty04_mem_key_t *kty04_pub_key, *kty04_key;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_get_pub", __LINE__, LOGERROR);
    return NULL;
  }

  kty04_key = (kty04_mem_key_t *) key->key;

  if(!(pub_key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mem_key_get_pub", __LINE__, errno, LOGERROR);
    return NULL;
  }

  
  /* The public part of the member key are all fields except x' (xx) */
  if(!(kty04_pub_key = (kty04_mem_key_t *) malloc(sizeof(kty04_mem_key_t)))) {
    mem_free(pub_key); pub_key = NULL;
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mem_key_get_pub", __LINE__, errno, LOGERROR);
    return NULL;
  }

  /* Initialize and set the fields */
  if(!(kty04_pub_key->A = bigz_init_set(kty04_key->A))) {
    free(pub_key); pub_key = NULL;
    free(kty04_pub_key); kty04_pub_key = NULL;
    return NULL;
  }
  
  if(!(kty04_pub_key->C = bigz_init_set(kty04_key->C))) {
    bigz_free(kty04_pub_key->A);
    free(pub_key); pub_key = NULL;
    free(kty04_pub_key); kty04_pub_key = NULL;
    return NULL;
  }

  if(!(kty04_pub_key->x = bigz_init_set(kty04_key->x))) {
    bigz_free(kty04_pub_key->A); bigz_free(kty04_pub_key->C);
    free(pub_key); pub_key = NULL;
    free(kty04_pub_key); kty04_pub_key = NULL;
    return NULL;
  }

  if(!(kty04_pub_key->e = bigz_init_set(kty04_key->e))) {
    bigz_free(kty04_pub_key->A); bigz_free(kty04_pub_key->C);
    bigz_free(kty04_pub_key->e);
    free(pub_key); pub_key = NULL;
    free(kty04_pub_key); kty04_pub_key = NULL;
    return NULL;
  }

  /* Set the remaining elements to NULL */
  kty04_pub_key->xx = NULL;
  
  pub_key->scheme = GROUPSIG_KTY04_CODE;
  pub_key->key = kty04_pub_key;
   
  return pub_key;

}

/* int mem_key_set_prv(kty04_mem_key_t *dst, kty04_mem_key_t *src); */
/* int mem_key_set_pub(kty04_mem_key_t *dst, kty04_mem_key_t *src); */

char* kty04_mem_key_to_string(groupsig_key_t *key) {

  kty04_mem_key_t *kty04_key;
  char *sA, *sC, *sx, *sxx, *se, *skey;
  uint32_t length;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  sA=NULL; sC=NULL; sx=NULL; sxx=NULL; se=NULL; skey=NULL;
  kty04_key = (kty04_mem_key_t *) key->key;

  sA = bigz_get_str(10, kty04_key->A);
  sC = bigz_get_str(10, kty04_key->C);
  sx = bigz_get_str(10, kty04_key->x);
  sxx = bigz_get_str(10, kty04_key->xx);
  se = bigz_get_str(10, kty04_key->e);

  if(!sA || !sC || !sx || !sxx || !se) {
    goto to_string_error;
  }

  length = strlen(sA)+strlen("A: \n")+strlen(sC)+strlen("C: \n")+
    strlen(sx)+strlen("x: \n")+strlen(sxx)+strlen("x': \n")+
    strlen(se)+strlen("e: \n");

  if(!(skey = (char *) malloc(sizeof(char)*(length+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mem_key_to_string", __LINE__, 
      errno, LOGERROR);
    goto to_string_error;
  }

  memset(skey, 0, sizeof(char)*(length+1));

  sprintf(skey, 
    "A: %s\n"
    "C: %s\n"
    "x: %s\n"
    "x': %s\n"
    "e: %s\n\n",
    sA, sC, sx, sxx, se);

 to_string_error:

  if(sA) { free(sA); sA = NULL; }
  if(sC) { free(sC); sC = NULL; }
  if(sx) { free(sx); sx = NULL; }
  if(sxx) { free(sxx); sxx = NULL; }
  if(se) { free(se); se = NULL; }  

  return skey;

}

char* kty04_mem_key_prv_to_string(groupsig_key_t *key) {

  kty04_mem_key_t *kty04_key;
  char *sxx, *skey;
  uint32_t length;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_prv_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  sxx=NULL; skey=NULL;
  kty04_key = (kty04_mem_key_t *) key->key;

  if(!(sxx = bigz_get_str(10, kty04_key->xx))) {
    return NULL;
  }

  length = strlen(sxx)+strlen("x': \n");

  if(!(skey = (char *) malloc(sizeof(char)*(length+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mem_key_prv_to_string", __LINE__, 
      errno, LOGERROR);
    free(sxx); sxx = NULL;
    return NULL;
  }

  memset(skey, 0, sizeof(char)*(length+1));
  sprintf(skey, "x': %s\n", sxx);

  mem_free(sxx); sxx = NULL;

  return skey;

}

char* kty04_mem_key_pub_to_string(groupsig_key_t *key) {

  kty04_mem_key_t *kty04_key;
  char *sA, *sC, *sx, *se, *skey;
  uint32_t length;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_pub_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  sA=NULL; sC=NULL; sx=NULL; se=NULL; skey=NULL;
  kty04_key = (kty04_mem_key_t *) key->key;

  sA = bigz_get_str(10, kty04_key->A);
  sC = bigz_get_str(10, kty04_key->C);
  sx = bigz_get_str(10, kty04_key->x);
  se = bigz_get_str(10, kty04_key->e);

  if(!sA || !sC || !sx || !se) goto mem_key_pub_to_string_end;

  length = strlen(sA)+strlen("A: \n")+strlen(sC)+strlen("C: \n")+
    strlen(sx)+strlen("x: \n")+strlen(se)+strlen("e: \n");

  if(!(skey = (char *) malloc(sizeof(char)*(length+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mem_key_pub_to_string", __LINE__, 
      errno, LOGERROR);
    goto mem_key_pub_to_string_end;
  }
  
  memset(skey, 0, sizeof(char)*(length+1));
  
  sprintf(skey, 
    "A: %s\n"
    "C: %s\n"
    "x: %s\n"
    "e: %s\n\n",
    sA, sC, sx, se);
  
 mem_key_pub_to_string_end:

  if(sA) { mem_free(sA); sA = NULL; }
  if(sC) { mem_free(sC); sC = NULL; }
  if(sx) { mem_free(sx); sx = NULL; }
  if(se) { mem_free(se); se = NULL; }  

  return skey;

}

int kty04_mem_key_export(groupsig_key_t *key, groupsig_key_format_t format, void *dst) {

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_export", __LINE__, LOGERROR);
    return IERROR;
  }
  exim_t wrap = {key->key, &_exim_h };


  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_mem_key_export", __LINE__,
        "The specified format is not supported.", LOGERROR);
    return IERROR;
  }

  /* Apply the specified conversion */
  return exim_export(&wrap, format, dst);
  
}

int kty04_mem_key_export_pub(groupsig_key_t *key, groupsig_key_format_t format, void *dst) {

  groupsig_key_t *pub_key;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_export_pub", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(pub_key = kty04_mem_key_get_pub(key))) {
    return IERROR;
  }

  if(kty04_mem_key_export(pub_key, format, dst) == IERROR) {
    kty04_mem_key_free(pub_key);
    return IERROR;
  }
  
  kty04_mem_key_free(pub_key);

  return IOK;

}

int kty04_mem_key_export_prv(groupsig_key_t *key, groupsig_key_format_t format, void *dst) {

  groupsig_key_t *prv_key;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_export_prv", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(prv_key = kty04_mem_key_get_prv(key))) {
    return IERROR;
  }

  if(kty04_mem_key_export(prv_key, format, dst) == IERROR) {
    kty04_mem_key_free(prv_key);
    return IERROR;
  }

  kty04_mem_key_free(prv_key);

  return IOK;

}

groupsig_key_t* kty04_mem_key_import(groupsig_key_format_t format, void *source) {
  exim_t wrap = {NULL, &_exim_h };

  if(!source) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_mem_key_import", __LINE__,
       "The specified format is not supported.", LOGERROR);
    return NULL;    
  }

  /** @todo For now, we just receive files. However, when included support for
      BBDD, etc., we'll have to deal with that here. In short, the idea is first
      to fetch the key from the specific source, returning an "object" of whatever
      type (e.g. a base64 string for base64 encoded keys in either a file or a BBDD)
  and then deal with that "objects" in each private key import function */

  /* Apply the specified conversion */
  if(exim_import(format, source, &wrap) == IOK){
    return wrap.eximable;
  }

  return NULL;

}

groupsig_key_t* kty04_mem_key_import_prv(groupsig_key_format_t format, void *source) { 

  if(!source) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_import_prv", __LINE__, LOGERROR);
    return NULL;
  }
  
  /** @todo This may also be returning the public part! */
  return kty04_mem_key_import(format, source);

}

groupsig_key_t* kty04_mem_key_import_pub(groupsig_key_format_t format, void *source) {

  if(!source) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mem_key_import_pub", __LINE__, LOGERROR);
    return NULL;
  }

  /** @todo This may also be returning the private part! */
  return kty04_mem_key_import(format, source);

}

/* mem_key.c ends here */
