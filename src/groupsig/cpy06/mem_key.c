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

#include "cpy06.h"
#include "groupsig/cpy06/mem_key.h"
#include "wrappers/base64.h"
#include "wrappers/pbc_ext.h"
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

  for(i=0; i<CPY06_SUPPORTED_KEY_FORMATS_N; i++) {
    if(CPY06_SUPPORTED_KEY_FORMATS[i] == format) {
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
static int _get_size_bytearray_null(exim_t *obj){
  int size;
  byte_t *bytes_params;
  uint64_t size_params;
  cpy06_sysenv_t *cpy06_sysenv;
  if(!obj || !obj->eximable){
    return -1;
  }
  cpy06_mem_key_t *key = (cpy06_mem_key_t*)obj->eximable;
  if(!key->x[0].data || !key->t[0].data || !key->A[0].data){
      LOG_EINVAL(&logger, __FILE__, "_get_size_bytearray_null", __LINE__, LOGERROR);
      return -1;
  }

  cpy06_sysenv = sysenv->data;

  bytes_params = NULL;
  if(pbcext_dump_param_bytes(&bytes_params, &size_params, cpy06_sysenv->param) == IERROR) {
    return IERROR;
  }

  size = element_length_in_bytes(key->x)+element_length_in_bytes(key->t)+
    element_length_in_bytes(key->A)+size_params+sizeof(int)*4+2;

  return size;
}

/**
 * @fn static int _export_fd(exim_t* obj, FILE *fd)
 * @brief Writes a bytearray representation of the given exim object to a
 * file descriptor with format:
 *
 *  | CPY06_CODE | KEYTYPE | size_params | params | size_x | x | size_t | t | size_A | A |
 *
 * @param[in] key The key to export.
 * @param[in, out] fd An open filestream to write to.
 *
 * @return IOK or IERROR
 */
static int _export_fd(exim_t* obj, FILE *fd) {
  uint8_t code, type;
  cpy06_sysenv_t *cpy06_sysenv;

  if(!obj || !obj->eximable || !fd) {
    LOG_EINVAL(&logger, __FILE__, "_export_fd", __LINE__, LOGERROR);
    return IERROR;
  }
  cpy06_mem_key_t *key = (cpy06_mem_key_t*)obj->eximable;
  if(!key->x[0].data || !key->t[0].data || !key->A[0].data){
      LOG_EINVAL(&logger, __FILE__, "_export_fd", __LINE__, LOGERROR);
      return IERROR;
  }
  cpy06_sysenv = sysenv->data;

  /* Dump GROUPSIG_CPY06_CODE */
  code = GROUPSIG_CPY06_CODE;
  if(fwrite(&code, sizeof(byte_t), 1, fd) != 1) {
      return IERROR;
  }
  /* Dump key type */
  type = GROUPSIG_KEY_MEMKEY;
  if(fwrite(&type, sizeof(byte_t), 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "_export_fd", __LINE__,
          errno, LOGERROR);
    return IERROR;
  }

  /* Dump params */
  if(pbcext_dump_param_fd(cpy06_sysenv->param, fd) == IERROR) {
    return IERROR;
  }

  /* Dump x */
  if(pbcext_dump_element_fd(key->x, fd) == IERROR) {
    return IERROR;
  }

  /* Dump t */
  if(pbcext_dump_element_fd(key->t, fd) == IERROR) {
    return IERROR;
  }

  /* Dump A */
  if(pbcext_dump_element_fd(key->A, fd) == IERROR) {
    return IERROR;
  }

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
  groupsig_key_t *key;
  cpy06_mem_key_t *cpy06_key;
  cpy06_sysenv_t *cpy06_sysenv;
  uint8_t type, scheme;

  if(!fd || !obj) {
    LOG_EINVAL(&logger, __FILE__, "_import_fd", __LINE__,
           LOGERROR);
    return IERROR;
  }

  if(!(key = cpy06_mem_key_init())) {
    return IERROR;
  }

  cpy06_key = key->key;

  /* First byte: scheme */
  if(fread(&scheme, sizeof(byte_t), 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "_import_fd", __LINE__,
          errno, LOGERROR);
    cpy06_mem_key_free(key); key = NULL;
    return IERROR;
  }

  /* Next byte: key type */
  if(fread(&type, sizeof(byte_t), 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "_import_fd", __LINE__,
          errno, LOGERROR);
    cpy06_mem_key_free(key); key = NULL;
    return IERROR;
  }

  /* Get the params if sysenv->data is uninitialized */
  if(!sysenv->data) {

    /* Copy the param and pairing to the CPY06 internal environment */
    /* By setting the environment, we avoid having to keep a copy of params
       and pairing in manager/member keys and signatures, crls, gmls... */
    if(!(cpy06_sysenv = (cpy06_sysenv_t *) mem_malloc(sizeof(cpy06_sysenv_t)))) {
      cpy06_mem_key_free(key); key = NULL;
      return IERROR;
    }

    /* Get the params */
    if(pbcext_get_param_fd(cpy06_sysenv->param, fd) == IERROR) {
      cpy06_mem_key_free(key); key = NULL;
      return IERROR;
    }

    pairing_init_pbc_param(cpy06_sysenv->pairing, cpy06_sysenv->param);

    if(cpy06_sysenv_update(cpy06_sysenv) == IERROR) {
      cpy06_mem_key_free(key); key = NULL;
      pbc_param_clear(cpy06_sysenv->param);
      mem_free(cpy06_sysenv); cpy06_sysenv = NULL;
      return IERROR;
    }

  } else { /* Else, skip it */

    if (pbcext_skip_param_fd(fd) == IERROR) {
      cpy06_mem_key_free(key); key = NULL;
    }
    cpy06_sysenv = sysenv->data;

  }

  /* Get x */
  element_init_Zr(cpy06_key->x, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->x, fd) == IERROR) {
    cpy06_mem_key_free(key); key = NULL;
    return IERROR;
  }

  /* Get t */
  element_init_Zr(cpy06_key->t, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->t, fd) == IERROR) {
    cpy06_mem_key_free(key); key = NULL;
    return IERROR;
  }

  /* Get A */
  element_init_G1(cpy06_key->A, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->A, fd) == IERROR) {
    cpy06_mem_key_free(key); key = NULL;
    return IERROR;
  }

  obj->eximable = (void*) key;
  return IOK;

}

/* Export/import handle definition */

static exim_handle_t _exim_h = {
  &_get_size_bytearray_null,
  &_export_fd,
  &_import_fd,
};

/* Public functions */

groupsig_key_t* cpy06_mem_key_init() {
  
  groupsig_key_t *key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (cpy06_mem_key_t *) mem_malloc(sizeof(cpy06_mem_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_CPY06_CODE;

  return key;

}

int cpy06_mem_key_free(groupsig_key_t *key) {

  cpy06_mem_key_t *cpy06_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_mem_key_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_mem_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {
    cpy06_key = key->key;
    if(cpy06_key->x[0].data) element_clear(cpy06_key->x);
    if(cpy06_key->t[0].data) element_clear(cpy06_key->t);
    if(cpy06_key->A[0].data) element_clear(cpy06_key->A);
    mem_free(key->key);
    key->key = NULL;
  }
  
  mem_free(key);

  return IOK;

}

int cpy06_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  cpy06_mem_key_t *cpy06_dst, *cpy06_src;

  if(!dst || dst->scheme != GROUPSIG_CPY06_CODE ||
     !src || src->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_mem_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  cpy06_dst = dst->key;
  cpy06_src = src->key;

  /* Copy the elements */
  element_init_same_as(cpy06_dst->x, cpy06_src->x);
  element_set(cpy06_dst->x, cpy06_src->x);
  element_init_same_as(cpy06_dst->t, cpy06_src->t);
  element_set(cpy06_dst->t, cpy06_src->t);
  element_init_same_as(cpy06_dst->A, cpy06_src->A);
  element_set(cpy06_dst->A, cpy06_src->A);

  return IOK;

}

int cpy06_mem_key_get_size_in_format(groupsig_key_t *key, groupsig_key_format_t format) {

  if(!key || key->scheme != GROUPSIG_CPY06_CODE ||
     !_is_supported_format(format)) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_mem_key_get_size_in_format", __LINE__, LOGERROR);
    return -1;
  }

  exim_t wrap = {key->key, &_exim_h };
  return exim_get_size_in_format(&wrap, format);

}

char* cpy06_mem_key_to_string(groupsig_key_t *key) {

  char *s;
  int l, l_x, l_t, l_A, o;

  if(!key || key->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_mem_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  l_x = element_length_in_bytes(((cpy06_mem_key_t *) key->key)->x);
  l_t = element_length_in_bytes(((cpy06_mem_key_t *) key->key)->t);
  l_A = element_length_in_bytes(((cpy06_mem_key_t *) key->key)->A);
  l = (l_x + l_t + l_A) * 28; // @todo (28 = 3.5 * 8 ~ 3.33 * 8)
  l += strlen("X: \nt: \nA:\n");

  if(!(s = (char *) mem_malloc(sizeof(char)*(l+1)))) {
    return NULL;
  }

  sprintf(s, "X: "); o = strlen("X: ");
  l_x = element_snprint(&s[o], l, ((cpy06_mem_key_t *) key->key)->x); o += l_x; 
  sprintf(&s[o], "\nt: "); o += strlen("\nt: ");
  l_t = element_snprint(&s[o], l, ((cpy06_mem_key_t *) key->key)->t); o += l_t;
  sprintf(&s[o], "\nA: "); o += strlen("\nA: ");
  l_A = element_snprint(&s[o], l, ((cpy06_mem_key_t *) key->key)->A); o += l_A;
  sprintf(&s[o], "\n");

  return s;

}

int cpy06_mem_key_export(groupsig_key_t *key, groupsig_key_format_t format, void *dst) {

  if(!key || key->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_mem_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_mem_key_export", __LINE__,
		   "The specified format is not supported.", LOGERROR);
    return IERROR;
  }

  /* Apply the specified conversion */
  exim_t wrap = {key->key, &_exim_h };
  return exim_export(&wrap, format, dst);
  
}

groupsig_key_t* cpy06_mem_key_import(groupsig_key_format_t format, void *source) {

  if(!source) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_mem_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_mem_key_import", __LINE__,
  		   "The specified format is not supported.", LOGERROR);
    return NULL;
  }

  exim_t wrap = {NULL, &_exim_h };
  if(exim_import(format, source, &wrap) != IOK){
    return NULL;
  }

  return wrap.eximable;

}

/* mem_key.c ends here */
