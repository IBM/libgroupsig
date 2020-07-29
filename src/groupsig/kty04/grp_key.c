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

#include "sysenv.h"
#include "sys/mem.h"
#include "misc/misc.h"
#include "exim.h"
#include "wrappers/base64.h"

#include "kty04.h"
#include "groupsig/kty04/grp_key.h"

/* Internal constants */
#define MAX_SNU 100
#define MAX_SEPSILON 100

/* static (private) functions */

static int _grp_key_free_spheres(kty04_grp_key_t *key) {

  int rc;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "_grp_key_free_spheres", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  rc = IOK;
  if(key->lambda) {
    rc += sphere_free(key->lambda);
  }

  if(key->M) {
    rc += sphere_free(key->M);
  }

  if(key->gamma) {
    rc += sphere_free(key->gamma);
  }

  if(key->inner_lambda) {
    rc += sphere_free(key->inner_lambda);
  }

  if(key->inner_M) {
    rc += sphere_free(key->inner_M);
  }

  if(key->inner_gamma) {
    rc += sphere_free(key->inner_gamma);
  }

  if(rc) rc = IERROR;
  
  return rc;

}

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
static int _get_size_bytearray_null(exim_t *obj){
  int size;
  kty04_grp_key_t* key = (kty04_grp_key_t*)obj->eximable;
  byte_t *bn=NULL, *ba=NULL, *ba0=NULL, *bb=NULL, *bg=NULL, *bh=NULL, *by=NULL;
  size_t sn = 0, sa = 0, sa0 = 0, sb = 0, sg = 0, sh = 0, sy = 0;

  /* Export the variables to binary data */
  if(!(bn = bigz_export(key->n, &sn)))
    return -1;
  if(!(ba = bigz_export(key->a, &sa)))
    return -1;
  if(!(ba0 = bigz_export(key->a0, &sa0)))
    return -1;
  if(!(bb = bigz_export(key->b, &sb)))
    return -1;
  if(!(bg = bigz_export(key->g, &sg)))
    return -1;
  if(!(bh = bigz_export(key->h, &sh)))
    return -1;
  if(!(by = bigz_export(key->y, &sy)))
    return -1;

  /* To separate the different values, and be able to parse them later, we use
     the 'syntax': "'n='<n>'a='<a>'a0='<a0>'b='<b>'g='<g>'h='<h>'y='<y>'E='<epsilon>'nu='<nu>'k='<k>",
     where the values between '' are printed in ASCII, and the <x> are the binary
     data obtained above. Therefore, the total length of the group key will be
     8*2+2*3+sn+sa+sa0+sb+sg+sh+sy+3*sizeof(uint64_t).
     @todo although does not seem very probable, it is possible that the binary
     data of n, e, ... contains the ASCII codes of 'n=', 'e=', etc.. This will
     obviously lead to program malfunction...
  */

  /* We only need their sizes */
  mem_free(bn); bn = NULL;
  mem_free(ba); ba = NULL;
  mem_free(ba0); ba0 = NULL;
  mem_free(bb); bb = NULL;
  mem_free(bg); bg = NULL;
  mem_free(bh); bh = NULL; 
  mem_free(by); by = NULL; 

  size = 7*sizeof(size_t)+sn+sa+sa0+sb+sg+sh+sy+3*sizeof(uint64_t);
  return size;
}

/**
 * @fn static int _export_fd(exim_t* obj, FILE *fd)
 * @brief Writes a bytearray representation of the given exim object to a
 * file descriptor with format:
 *
 * | size n | n | size a | a | size a0 | a0 | size b | b | size g | g |
 * | size h | h | size y | y | epsilon | nu | k |
 * "'n='<n>'a='<a>'a0='<a0>'b='<b>'g='<g>'h='<h>'y='<y>'nu='<nu>'E='<epsilon>'k='<k>"
 *
 * @param[in] key The key to export.
 * @param[in, out] fd An open filestream to write to.
 *
 * @return IOK or IERROR
 */
static int _export_fd(exim_t* obj, FILE *fd) {
  kty04_grp_key_t *key = (kty04_grp_key_t *)obj->eximable;
  /* gnutls_datum_t datum,  */
  kty04_grp_key_t *gkey;
  uint32_t count;
  int rc;

  if(!key) {
    LOG_EINVAL(&logger, __FILE__, "_grp_key_export_file_null_b64", __LINE__, LOGERROR);
    return IERROR;
  }

  gkey = (kty04_grp_key_t *) key; rc = IOK;
  if(bigz_dump_bigz_fd(gkey->n, fd, 0) != IOK) GOTOENDRC(IERROR, _export_fd);
  if(bigz_dump_bigz_fd(gkey->a, fd, 0) != IOK) GOTOENDRC(IERROR, _export_fd);
  if(bigz_dump_bigz_fd(gkey->a0, fd, 0) != IOK) GOTOENDRC(IERROR, _export_fd);
  if(bigz_dump_bigz_fd(gkey->b, fd, 0) != IOK) GOTOENDRC(IERROR, _export_fd);
  if(bigz_dump_bigz_fd(gkey->g, fd, 0) != IOK) GOTOENDRC(IERROR, _export_fd);
  if(bigz_dump_bigz_fd(gkey->h, fd, 0) != IOK) GOTOENDRC(IERROR, _export_fd);
  if(bigz_dump_bigz_fd(gkey->y, fd, 0) != IOK) GOTOENDRC(IERROR, _export_fd);

  count = 0;
  count += fwrite(&gkey->epsilon, sizeof(uint64_t), 1, fd);
  count += fwrite(&gkey->nu, sizeof(uint64_t), 1, fd);
  count += fwrite(&gkey->k, sizeof(uint64_t), 1, fd);

  if(count != 3){
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_export_fd", __LINE__,
              ENOTSUP, "Export failure.", LOGERROR);
    GOTOENDRC(IERROR, _export_fd);
  }

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
static int _import_fd(FILE *fd, exim_t* obj) {
  groupsig_key_t *key;
  kty04_grp_key_t *kty04_key;
  bigz_t n, a, a0, b, g, h, y;
  uint64_t nu, epsilon, k;
  int rc;
  uint8_t count;

  rc = IOK;

  if(bigz_get_bigz_fd(&n, fd, 0) != IOK) GOTOENDRC(IERROR, _import_fd);
  if(bigz_get_bigz_fd(&a, fd, 0) != IOK) GOTOENDRC(IERROR, _import_fd);
  if(bigz_get_bigz_fd(&a0, fd, 0) != IOK) GOTOENDRC(IERROR, _import_fd);
  if(bigz_get_bigz_fd(&b, fd, 0) != IOK) GOTOENDRC(IERROR, _import_fd);
  if(bigz_get_bigz_fd(&g, fd, 0) != IOK) GOTOENDRC(IERROR, _import_fd);
  if(bigz_get_bigz_fd(&h, fd, 0) != IOK) GOTOENDRC(IERROR, _import_fd);
  if(bigz_get_bigz_fd(&y, fd, 0) != IOK) GOTOENDRC(IERROR, _import_fd);

  count = 0;
  count += fread(&epsilon, sizeof(uint64_t), 1, fd);
  count += fread(&nu, sizeof(uint64_t), 1, fd);
  count += fread(&k, sizeof(uint64_t), 1, fd);

  if(count != 3) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_import_fd", __LINE__,
              EDQUOT, "Invalid group key file", LOGERROR);
    GOTOENDRC(IERROR, _import_fd);
  }

  if(!(key = kty04_grp_key_init())) GOTOENDRC(IERROR, _import_fd);

  kty04_key = key->key;
  if(bigz_set(kty04_key->n, n) == IERROR) GOTOENDRC(IERROR, _import_fd);
  if(bigz_set(kty04_key->a, a) == IERROR) GOTOENDRC(IERROR, _import_fd);
  if(bigz_set(kty04_key->a0, a0) == IERROR) GOTOENDRC(IERROR, _import_fd);
  if(bigz_set(kty04_key->b, b) == IERROR) GOTOENDRC(IERROR, _import_fd);
  if(bigz_set(kty04_key->g, g) == IERROR) GOTOENDRC(IERROR, _import_fd);
  if(bigz_set(kty04_key->h, h) == IERROR) GOTOENDRC(IERROR, _import_fd);
  if(bigz_set(kty04_key->y, y) == IERROR) GOTOENDRC(IERROR, _import_fd);
  kty04_key->nu = nu;
  kty04_key->epsilon = epsilon;
  kty04_key->k = k;
  
  /* Recover the spheres from the read parameters */
  if(kty04_grp_key_set_spheres_std(kty04_key) == IERROR) rc = IERROR;

  _import_fd_end:

  /* If any of the following variables is NULL it means that
     an error has occured */
  if(n) bigz_free(n); else rc = IERROR;
  if(a) bigz_free(a); else rc = IERROR;
  if(a0) bigz_free(a0); else rc = IERROR;
  if(b) bigz_free(b); else rc = IERROR;
  if(g) bigz_free(g); else rc = IERROR;
  if(h) bigz_free(h); else rc = IERROR;
  if(y) bigz_free(y); else rc = IERROR;

  if(rc == IERROR) {
    if(key) kty04_grp_key_free(key);
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


/* "Public" functions */

groupsig_key_t* kty04_grp_key_init() {

  groupsig_key_t *key;
  kty04_grp_key_t *kty04_key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_grp_key_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  if(!(kty04_key = (kty04_grp_key_t *) malloc(sizeof(kty04_grp_key_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_grp_key_init", __LINE__, errno, LOGERROR);
    mem_free(key); key = NULL;
    return NULL;
  }

  kty04_key->n = NULL; kty04_key->a = NULL; kty04_key->a0 = NULL; 
  kty04_key->b = NULL; kty04_key->b = NULL; kty04_key->g = NULL; 
  kty04_key->h = NULL; kty04_key->y = NULL; kty04_key->epsilon = 0; 
  kty04_key->nu = 0; kty04_key->k = 0; kty04_key->lambda = NULL; 
  kty04_key->inner_lambda = NULL; kty04_key->M = NULL; kty04_key->inner_M = NULL; 
  kty04_key->gamma = NULL; kty04_key->inner_gamma = NULL;
  
  if(!(kty04_key->n = bigz_init())) goto init_err;
  if(!(kty04_key->a = bigz_init())) goto init_err;
  if(!(kty04_key->a0 = bigz_init())) goto init_err;
  if(!(kty04_key->b = bigz_init())) goto init_err;
  if(!(kty04_key->g = bigz_init())) goto init_err;
  if(!(kty04_key->h = bigz_init())) goto init_err;
  if(!(kty04_key->y = bigz_init())) goto init_err;
  kty04_key->lambda = NULL;
  kty04_key->M = NULL;
  kty04_key->gamma = NULL;
  kty04_key->inner_lambda = NULL;
  kty04_key->inner_M = NULL;
  kty04_key->inner_gamma = NULL;

  key->scheme = GROUPSIG_KTY04_CODE;
  key->key = kty04_key;

  return key;

 init_err:

  if(kty04_key->n) bigz_free(kty04_key->n);
  if(kty04_key->a) bigz_free(kty04_key->a);
  if(kty04_key->a0) bigz_free(kty04_key->a0);
  if(kty04_key->b) bigz_free(kty04_key->b);
  if(kty04_key->g) bigz_free(kty04_key->g);
  if(kty04_key->h) bigz_free(kty04_key->h);
  if(kty04_key->y) bigz_free(kty04_key->y);
  if(kty04_key) { free(kty04_key); kty04_key = NULL; }
  if(key) { mem_free(key); key = NULL; }

  return NULL;

}

int kty04_grp_key_free(groupsig_key_t *key) {

  kty04_grp_key_t *kty04_key;
  int rc;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_grp_key_free", __LINE__, LOGWARN);
    return IERROR;
  }

  kty04_key = (kty04_grp_key_t *) key->key;
  rc = IOK;

  if(kty04_key->n) { rc += bigz_free(kty04_key->n); kty04_key->n = NULL; }
  if(kty04_key->a) { rc += bigz_free(kty04_key->a); kty04_key->a = NULL; }
  if(kty04_key->a0) { rc += bigz_free(kty04_key->a0); kty04_key->a0 = NULL; }
  if(kty04_key->b) { rc += bigz_free(kty04_key->b); kty04_key->b = NULL; }
  if(kty04_key->g) { rc += bigz_free(kty04_key->g); kty04_key->g = NULL; }
  if(kty04_key->h) { rc += bigz_free(kty04_key->h); kty04_key->h = NULL; }
  if(kty04_key->y) { rc += bigz_free(kty04_key->y); kty04_key->y = NULL; }

  rc += _grp_key_free_spheres(kty04_key);

  free(kty04_key); kty04_key = NULL;
  free(key);

  if(rc) rc = IERROR;

  return rc;

}

int kty04_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  kty04_grp_key_t *kty04_dst, *kty04_src;

  if(!dst || dst->scheme != GROUPSIG_KTY04_CODE ||
     !src || src->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_grp_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  kty04_dst = (kty04_grp_key_t *) dst->key;
  kty04_src = (kty04_grp_key_t *) src->key;
  
  if(bigz_set(kty04_dst->n, kty04_src->n) == IERROR) return IERROR;
  if(bigz_set(kty04_dst->a, kty04_src->a) == IERROR) return IERROR;
  if(bigz_set(kty04_dst->a0, kty04_src->a0) == IERROR) return IERROR;
  if(bigz_set(kty04_dst->b, kty04_src->b) == IERROR) return IERROR;
  if(bigz_set(kty04_dst->g, kty04_src->g) == IERROR) return IERROR;
  if(bigz_set(kty04_dst->h, kty04_src->h) == IERROR) return IERROR;
  if(bigz_set(kty04_dst->y, kty04_src->y) == IERROR) return IERROR;  

  kty04_dst->epsilon = kty04_src->epsilon;
  kty04_dst->nu = kty04_src->nu;
  kty04_dst->k = kty04_src->k;

  /* Copy the spheres */

  /* Lambda */
  if(!(kty04_dst->lambda = sphere_init())) {
    return IERROR;
  }
  if(bigz_set(kty04_dst->lambda->center, kty04_src->lambda->center) == IERROR) {
    sphere_free(kty04_dst->lambda);
    return IERROR;
  }
  if(bigz_set(kty04_dst->lambda->radius, kty04_src->lambda->radius) == IERROR) {
    sphere_free(kty04_dst->lambda);
    return IERROR;
  }

  /* Inner lambda */
  if(!(kty04_dst->inner_lambda = sphere_init())) {
    sphere_free(kty04_dst->lambda);
    return IERROR;
  }
  if(bigz_set(kty04_dst->inner_lambda->center, kty04_src->inner_lambda->center) == IERROR) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    return IERROR;
  }
  if(bigz_set(kty04_dst->inner_lambda->radius, kty04_src->inner_lambda->radius) == IERROR) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    return IERROR;
  }

  /* M */
  if(!(kty04_dst->M = sphere_init())) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    return IERROR;
  }
  if(bigz_set(kty04_dst->M->center, kty04_src->M->center) == IERROR) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->M);
    return IERROR;
  }
  if(bigz_set(kty04_dst->M->radius, kty04_src->M->radius) == IERROR) {
    sphere_free(kty04_dst->inner_lambda);
    sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->M);
    return IERROR;
  }

  /* Inner M */
  if(!(kty04_dst->inner_M = sphere_init())) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->M);
    return IERROR;
  }
  if(bigz_set(kty04_dst->inner_M->center, kty04_src->inner_M->center) == IERROR) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->inner_M); sphere_free(kty04_dst->M);
    return IERROR;
  }
  if(bigz_set(kty04_dst->inner_M->radius, kty04_src->inner_M->radius) == IERROR) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->inner_M); sphere_free(kty04_dst->M);
    return IERROR;
  }

  /* Gamma */
  if(!(kty04_dst->gamma = sphere_init())) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->inner_M); sphere_free(kty04_dst->M);
    return IERROR;
  }
  if(bigz_set(kty04_dst->gamma->center, kty04_src->gamma->center) == IERROR) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->inner_M); sphere_free(kty04_dst->M);
    sphere_free(kty04_dst->gamma);
    return IERROR;
  }
  if(bigz_set(kty04_dst->gamma->radius, kty04_src->gamma->radius) == IERROR) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->inner_M); sphere_free(kty04_dst->M);
    sphere_free(kty04_dst->gamma);
    return IERROR;
  }

  /* Inner gamma */
  if(!(kty04_dst->inner_gamma = sphere_init())) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->inner_M); sphere_free(kty04_dst->M);
    sphere_free(kty04_dst->gamma);
    return IERROR;
  }
  if(bigz_set(kty04_dst->inner_gamma->center, kty04_src->inner_gamma->center) == IERROR) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->inner_M); sphere_free(kty04_dst->M);
    sphere_free(kty04_dst->inner_gamma); sphere_free(kty04_dst->gamma);
    return IERROR;
  }
  if(bigz_set(kty04_dst->inner_gamma->radius, kty04_src->inner_gamma->radius) == IERROR) {
    sphere_free(kty04_dst->inner_lambda); sphere_free(kty04_dst->lambda);
    sphere_free(kty04_dst->inner_M); sphere_free(kty04_dst->M);
    sphere_free(kty04_dst->inner_gamma); sphere_free(kty04_dst->gamma);
    return IERROR;
  }
  
  return IOK;

}

int kty04_grp_key_get_size_in_format(groupsig_key_t *key, groupsig_key_format_t format) {
  exim_t wrap = {key->key, &_exim_h };
  if(!key || key->scheme != GROUPSIG_KTY04_CODE ||
     !_is_supported_format(format)) {
    LOG_EINVAL(&logger, __FILE__, "kty04_grp_key_get_size_in_format", __LINE__, LOGERROR);
    return -1;
  }

  return exim_get_size_in_format(&wrap, format);

}

int kty04_grp_key_export(groupsig_key_t *key, groupsig_key_format_t format, void *dst) {
  exim_t wrap = {(void*)key->key, &_exim_h };
  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_grp_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_grp_key_export", __LINE__,
		   "The specified format is not supported.", LOGERROR);
    return IERROR;
  }

  /* Apply the specified conversion */
  return exim_export(&wrap, format, dst);
  
}

groupsig_key_t* kty04_grp_key_import(groupsig_key_format_t format, void *source) {
  exim_t wrap = {NULL, &_exim_h };

  if(!source) {
    LOG_EINVAL(&logger, __FILE__, "kty04_grp_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_grp_key_import", __LINE__,
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

char* kty04_grp_key_to_string(groupsig_key_t *key) { 

  kty04_grp_key_t *gkey;
  char *sn, *sa, *sa0, *sb, *sg, *sh, *sy, *snu, *sepsilon, *sk, *skey;
  char *s_lambda, *s_inner_lambda, *s_M, *s_inner_M, *s_gamma, *s_inner_gamma;
  uint32_t skey_len;
  size_t bits;

  if(!key) {
    LOG_EINVAL(&logger, __FILE__, "grp_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  /* For each field, we have to add space for its name (i.e., for a, add space
     for printing "a: ", for a0 add space for "a0: ", and so on). Besides, a
     '\n' will be printed after each field. Also, we have to take into account 
     the spheres. For them, we will add    "lambda: ", "inner lambda: ", etc., 
     but without the '\n' because they are included by the called functions.
  */
  sn=NULL; sa=NULL; sa0=NULL; sb=NULL; sg=NULL; sh=NULL; sy=NULL; snu=NULL;
  sepsilon=NULL; sk=NULL; s_lambda=NULL; s_inner_lambda=NULL; s_M=NULL; 
  s_inner_M=NULL; s_gamma=NULL; s_inner_gamma=NULL; skey=NULL;

  gkey = (kty04_grp_key_t *) key->key;

  sn = bigz_get_str(10, gkey->n);
  sa = bigz_get_str(10, gkey->a);
  sa0 = bigz_get_str(10, gkey->a0);
  sb = bigz_get_str(10, gkey->b);
  sg = bigz_get_str(10, gkey->g);
  sh = bigz_get_str(10, gkey->h);
  sy = bigz_get_str(10, gkey->y);
  snu = misc_uint642string(gkey->nu);
  sepsilon = misc_uint642string(gkey->epsilon);
  sk = misc_uint642string(gkey->k);
 
  s_lambda = sphere_to_string(gkey->lambda);
  s_inner_lambda = sphere_to_string(gkey->inner_lambda);
  s_M = sphere_to_string(gkey->M);
  s_inner_M = sphere_to_string(gkey->inner_M);
  s_gamma = sphere_to_string(gkey->gamma);
  s_inner_gamma = sphere_to_string(gkey->inner_gamma);

  if(!sn || !sa || !sa0 || !sb || !sg || !sh || !sy ||
     !s_lambda || !s_inner_lambda || !s_M || !s_inner_M ||
     !s_gamma || !s_inner_gamma) {    
    goto grp_key_to_string_error;
  }

  errno = 0;
  bits = bigz_sizeinbase(gkey->n, 2);
  if(errno) goto grp_key_to_string_error;
    
  skey_len = 10 + // bits probably wont exceed 10 chars...
    strlen(sn)+strlen("n: ( bits)\n")+strlen(sa)+strlen("a: \n")+
    strlen(sa0)+strlen("a0: \n")+strlen(sb)+strlen("b: \n")+
    strlen(sg)+strlen("g: \n")+strlen(sh)+strlen("h: \n")+
    strlen(sy)+strlen("y: \n")+strlen("nu: \n")+strlen(snu)+
    strlen("epsilon: \n")+strlen(sepsilon)+strlen("k: \n")+strlen(sk)+
    strlen(s_lambda)+strlen("lambda: ")+strlen(s_inner_lambda)+
    strlen("inner lambda: ")+strlen(s_M)+strlen("M: ")+strlen(s_inner_M)+
    strlen("inner M: ")+strlen(s_gamma)+strlen("gamma: ")+
    strlen(s_inner_gamma)+strlen("inner gamma: ");

  if(!(skey = (char *) malloc(sizeof(char)*(skey_len+1)))) {
    goto grp_key_to_string_error;
  }

  memset(skey, 0, sizeof(char)*(skey_len+1));

  sprintf(skey, 
	  "n: %s (%ld bits)\n"
	  "a: %s\n"
	  "a0: %s\n"
	  "b: %s\n"
	  "g: %s\n"
	  "h: %s\n"
	  "y: %s\n"
	  "epsilon: %s\n"
	  "nu: %s\n"
	  "k: %s\n"
	  "lambda: %s"
	  "inner lambda: %s"
	  "M: %s"
	  "inner M: %s"
	  "gamma: %s"
	  "inner gamma: %s",
	  sn, bits, sa, sa0, sb, sg, sh, sy, sepsilon, snu, sk, s_lambda, s_inner_lambda, 
	  s_M, s_inner_M, s_gamma, s_inner_gamma);

 grp_key_to_string_error:

  if(sn) { free(sn); sn = NULL; }
  if(sa) { free(sa); sa = NULL; }
  if(sa0) { free(sa0); sa0 = NULL; }
  if(sb) { free(sb); sb = NULL; }
  if(sg) { free(sg); sg = NULL; }
  if(sh) { free(sh); sh = NULL; }
  if(sy) { free(sy); sy = NULL; }
  if(snu) { free(snu); snu = NULL; }
  if(sepsilon) { free(sepsilon); sepsilon = NULL; }
  if(sk) { free(sk); sk = NULL; }
  if(s_lambda) { free(s_lambda); s_lambda = NULL; }
  if(s_inner_lambda) { free(s_inner_lambda); s_inner_lambda = NULL; }
  if(s_M) { free(s_M); s_M = NULL; }
  if(s_inner_M) { free(s_inner_M); s_inner_M = NULL; }
  if(s_gamma) { free(s_gamma); s_gamma = NULL; }
  if(s_inner_gamma) { free(s_inner_gamma); s_inner_gamma = NULL; }

  return skey;

}

int kty04_grp_key_set_spheres_std(kty04_grp_key_t *key) { 

  bigz_t lcenter, mcenter, gcenter, lradius, mradius, gradius;
  int rc;

  if(!key) {
    LOG_EINVAL(&logger, __FILE__, "kty04_grp_key_set_spheres_std", __LINE__, LOGERROR);
    return IERROR;
  }

  lcenter = NULL; mcenter = NULL; gcenter = NULL;
  lradius = NULL; mradius = NULL; gradius = NULL;
  rc = IOK;

  /* The Lambda sphere is S(2^(nu/4-1), 2^(nu/4-1)) */
  if(!(key->lambda = sphere_init())) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(!(lcenter = bigz_init())) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_ui_pow_ui(lcenter, 2, key->nu/4-1) == IERROR) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(!(lradius = bigz_init_set(lcenter))) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_set(key->lambda->center, lcenter) == IERROR) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_set(key->lambda->radius, lradius) == IERROR) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);

  /* The M sphere is S(2^(nu/2-1), 2^(nu/2-1)) */
  if(!(key->M = sphere_init())) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(!(mcenter = bigz_init())) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_ui_pow_ui(mcenter, 2, key->nu/2-1) == IERROR) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(!(mradius = bigz_init_set(mcenter))) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_set(key->M->center, mcenter) == IERROR) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_set(key->M->radius, mradius) == IERROR) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);

  /* The Gamma sphere is S(2^(3*nu/4)+2^(nu/4-1), 2^(nu/4-1)) */  
  if(!(key->gamma = sphere_init())) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(!(gradius = bigz_init())) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_ui_pow_ui(gradius, 2, key->nu/4-1) == IERROR) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(!(gcenter = bigz_init())) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_ui_pow_ui(gcenter, 2, 3*key->nu/4) == IERROR) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_add(gcenter, gcenter, gradius) == IERROR)  
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_set(key->gamma->center, gcenter) == IERROR) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(bigz_set(key->gamma->radius, gradius) == IERROR) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);

  /* Initialize the inner spheres and set them */

  /* Inner Lambda */
  if(!(key->inner_lambda = sphere_init())) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(sphere_get_inner(key->lambda, key->epsilon, key->k, 
		      key->inner_lambda) == IERROR) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);

  /* Inner M */
  if(!(key->inner_M = sphere_init())) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(sphere_get_inner(key->M, key->epsilon, key->k, 
		      key->inner_M) == IERROR) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);

  /* Inner Gamma */
  if(!(key->inner_gamma = sphere_init())) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  if(sphere_get_inner(key->gamma, key->epsilon, key->k, 
		      key->inner_gamma) == IERROR) 
    GOTOENDRC(IERROR, kty04_grp_key_set_spheres_std);
  
 kty04_grp_key_set_spheres_std_end:

  if(lcenter) bigz_free(lcenter);
  if(mcenter) bigz_free(mcenter);
  if(gcenter) bigz_free(gcenter);
  if(lradius) bigz_free(lradius);
  if(mradius) bigz_free(mradius);
  if(gradius) bigz_free(gradius);
  
  return rc;

}

/* grp_key.c ends here */
