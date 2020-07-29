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

#include "kty04.h"
#include "groupsig/kty04/mgr_key.h"
#include "misc/misc.h"
#include "exim.h"
#include "wrappers/base64.h"
#include "sys/mem.h"

/* private functions */

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
  int size = -1;
  kty04_mgr_key_t *mkey;
  byte_t *bp=NULL, *bq=NULL, *bx=NULL;
  size_t sp, sq, sx;

  if(!obj || !obj->eximable) {
    LOG_EINVAL(&logger, __FILE__, "_get_size_bytearray_null", __LINE__, LOGERROR);
    return -1;
  }

  mkey = (kty04_mgr_key_t *) obj->eximable;

  /* Export the variables to binary data */
  if(!(bp = bigz_export(mkey->p, &sp)))
    return -1;
  if(!(bq = bigz_export(mkey->q, &sq)))
    return -1;
  if(!(bx = bigz_export(mkey->x, &sx)))
    return -1;

  /* We only need their sizes */
  mem_free(bp); bp = NULL;
  mem_free(bq); bq = NULL;
  mem_free(bx); bx = NULL;

  /* To separate the different values, and be able to parse them later, we use
     the 'syntax': "'p='<p>'q='<q>'x'=<x>'nu='<nu>",
     where the values between '' are printed in ASCII, and the <x> are the binary
     data obtained above. Therefore, the total length of the manager key will be
     3*2+3+sp+sq+sx+sizeof(uint64_t)
     @todo although does not seem very probable, it is possible that the binary
     data of n, e, ... contains the ASCII codes of 'n=', 'e=', etc.. This will
     obviously lead to program malfunction...
  */

  size = 3*sizeof(size_t)+sp+sx+sq+sizeof(uint64_t);
  return size;
}


/**
 * @fn static int _export_fd(exim_t* obj, FILE *fd)
 * @brief Writes a bytearray representation of the given exim object to a
 * file descriptor with format:
 *
 * | size p | p | size q | q | size x | x | nu |
 * 'p='<p>'q='<q>'x'=<x>'nu='<nu>
 *
 * @param[in] key The key to export.
 * @param[in, out] fd An open filestream to write to.
 *
 * @return IOK or IERROR
 */
static int _export_fd(exim_t* obj, FILE *fd){
  kty04_mgr_key_t *mkey;
  uint32_t i;
  uint8_t count;
  int rc;
  mkey = (kty04_mgr_key_t *) obj->eximable; rc = IOK;

  if(bigz_dump_bigz_fd(mkey->p, fd, 0) != IOK) GOTOENDRC(IERROR, _export_fd);
  if(bigz_dump_bigz_fd(mkey->q, fd, 0) != IOK) GOTOENDRC(IERROR, _export_fd);
  if(bigz_dump_bigz_fd(mkey->x, fd, 0) != IOK) GOTOENDRC(IERROR, _export_fd);

  count = fwrite(&mkey->nu, sizeof(uint64_t), 1, fd);

  if(count != 1){
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
static int _import_fd(FILE *fd, exim_t* obj){
  bigz_t p, q, x;
  groupsig_key_t *key;
  kty04_mgr_key_t *kty04_key;
  uint64_t nu;
  uint8_t count;
  int rc;

  if(!fd || !obj ) {
    LOG_EINVAL(&logger, __FILE__, "_import_fd", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;

  if(bigz_get_bigz_fd(&p, fd, 0) != IOK) GOTOENDRC(IERROR, _import_fd);
  if(bigz_get_bigz_fd(&q, fd, 0) != IOK) GOTOENDRC(IERROR, _import_fd);
  if(bigz_get_bigz_fd(&x, fd, 0) != IOK) GOTOENDRC(IERROR, _import_fd);

  count = fread(&nu, sizeof(uint64_t), 1, fd);
  if(count != 1) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_import_fd", __LINE__,
              EDQUOT, "Invalid manager key file", LOGERROR);
    GOTOENDRC(IERROR, _import_fd);
  }

  if(!(key = kty04_mgr_key_init())) GOTOENDRC(IERROR, _import_fd);

  kty04_key = key->key;
  if(bigz_set(kty04_key->p, p) == IERROR)
    GOTOENDRC(IERROR, _import_fd);
  if(bigz_set(kty04_key->q, q) == IERROR)
    GOTOENDRC(IERROR, _import_fd);
  if(bigz_set(kty04_key->x, x) == IERROR)
    GOTOENDRC(IERROR, _import_fd);
  kty04_key->nu = nu;

  _import_fd_end:

  if(p) bigz_free(p); else rc = IERROR;
  if(q) bigz_free(q); else rc = IERROR;
  if(x) bigz_free(x); else rc = IERROR;

  if(rc == IERROR) {
    if(key) kty04_mgr_key_free(key);
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

/* public functions */

groupsig_key_t* kty04_mgr_key_init() {

  groupsig_key_t *key;
  kty04_mgr_key_t *kty04_key;

  if(!(key = (groupsig_key_t *) malloc(sizeof(groupsig_key_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mgr_key_init", __LINE__, errno, LOGERROR);
    return NULL;
  }  

  if(!(kty04_key = (kty04_mgr_key_t *) malloc(sizeof(kty04_mgr_key_t)))) {
    free(key); key = NULL;
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mgr_key_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  if(!(kty04_key->p = bigz_init())) { 
    free(key); key = NULL;
    free(kty04_key); kty04_key = NULL; 
    return NULL; 
  }

  if(!(kty04_key->q = bigz_init())) { 
    bigz_free(kty04_key->p);
    free(kty04_key); kty04_key = NULL;
    free(key); key = NULL;
    return NULL;
  }
  
  if(!(kty04_key->x = bigz_init())) {
    bigz_free(kty04_key->p); bigz_free(kty04_key->q);
    free(kty04_key); kty04_key = NULL;
    free(key); key = NULL;
    return NULL;
  }

  kty04_key->nu = 0;

  key->scheme = GROUPSIG_KTY04_CODE;
  key->key = kty04_key;
  
  return key;

}

int kty04_mgr_key_free(groupsig_key_t *key) {

  kty04_mgr_key_t *kty04_key;  

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
  LOG_EINVAL_MSG(&logger, __FILE__, "kty04_mgr_key_free", __LINE__, 
		 "Nothing to free.", LOGWARN);
    return IERROR;
  }

  kty04_key = (kty04_mgr_key_t *) key->key;

  if(kty04_key->p) { bigz_free(kty04_key->p); kty04_key->p = NULL; }
  if(kty04_key->q) { bigz_free(kty04_key->q); kty04_key->q = NULL; }
  if(kty04_key->x) { bigz_free(kty04_key->x); kty04_key->x = NULL; }

  free(kty04_key); kty04_key = NULL;
  free(key);

  return IOK;

}

int kty04_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  kty04_mgr_key_t *kty04_dst, *kty04_src;

  if(!dst || dst->scheme != GROUPSIG_KTY04_CODE ||
     !src || src->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  kty04_dst = (kty04_mgr_key_t *) dst->key;
  kty04_src = (kty04_mgr_key_t *) src->key;

  if(bigz_set(kty04_dst->p, kty04_src->p) == IERROR) return IERROR;
  if(bigz_set(kty04_dst->q, kty04_src->q) == IERROR) return IERROR;
  if(bigz_set(kty04_dst->x, kty04_src->x) == IERROR) return IERROR;
  kty04_dst->nu = kty04_src->nu;

  return IOK;

}

/* groupsig_key_t* kty04_mgr_key_get_prv(groupsig_key_t *key) { */

/*   if(!key || key->scheme != GROUPSIG_KTY04_CODE) { */
/*     LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_get_prv", __LINE__, LOGERROR); */
/*     return NULL; */
/*   } */

/*   /\* All the data in the key is private (except nu, which is  */
/*      only to save some computing time) *\/ */
/*   return key; */
  
/* } */

/* groupsig_key_t* kty04_mgr_key_get_pub(groupsig_key_t *key) { */

/*   if(!key || key->scheme != GROUPSIG_KTY04_CODE) { */
/*     LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_get_pub", __LINE__, LOGERROR); */
/*     return NULL; */
/*   } */

/*   /\* The manager key is completely private *\/ */
/*   return NULL; */

/* } */

/* int mgr_key_set_prv(kty04_mgr_key_t *dst, kty04_mgr_key_t *src); */
/* int mgr_key_set_pub(kty04_mgr_key_t *dst, kty04_mgr_key_t *src); */

int kty04_mgr_key_get_size_in_format(groupsig_key_t *key, groupsig_key_format_t format) {

  if(!key || key->scheme != GROUPSIG_KTY04_CODE ||
     !_is_supported_format(format)) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_get_size_in_format", __LINE__, LOGERROR);
    return -1;
  }

  exim_t wrap = {key->key, &_exim_h };
  return exim_get_size_in_format(&wrap, format);

}

int kty04_mgr_key_export(groupsig_key_t *key, groupsig_key_format_t format, void *dst) {
  exim_t wrap = {(void*)key->key, &_exim_h };
  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "kty04_mgr_key_export", __LINE__,
		   "The specified format is not supported.", LOGERROR);
    return IERROR;
  }

  /* Apply the specified conversion */
  return exim_export(&wrap, format, dst);
  
}

/* int kty04_mgr_key_export_pub(groupsig_key_t *key, groupsig_key_format_t format, void *dst) { */

/*   if(!key || key->scheme != GROUPSIG_KTY04_CODE) { */
/*     LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_export_pub", __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   return IERROR; */

/* } */

/* int kty04_mgr_key_export_prv(groupsig_key_t *key, groupsig_key_format_t format, void *dst) { */

/*   if(!key || key->scheme != GROUPSIG_KTY04_CODE) { */
/*     LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_export_prv", __LINE__, LOGERROR); */
/*     return IERROR; */
/*   } */

/*   return kty04_mgr_key_export(key, format, dst); */

/* } */

groupsig_key_t* kty04_mgr_key_import(groupsig_key_format_t format, void *source) {
  exim_t wrap = {NULL, &_exim_h };

  if(!source) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "mgr_key_import", __LINE__,
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

/* groupsig_key_t* kty04_mgr_key_import_prv(groupsig_key_format_t format, void *source) { */
/*   return kty04_mgr_key_import(format, source); */
/* } */

/* groupsig_key_t* kty04_mgr_key_import_pub(groupsig_key_format_t format, void *source) { */

/*   if(!source) { */
/*     LOG_EINVAL(&logger, __FILE__, "mgr_key_import_pub", __LINE__, LOGERROR); */
/*     return NULL; */
/*   } */

/*   return NULL; */
/* } */

char* kty04_mgr_key_to_string(groupsig_key_t *key) {

  kty04_mgr_key_t *mkey;
  char *sp, *sq, *sx, *snu, *skey;
  uint32_t length;

  if(!key || key->scheme != GROUPSIG_KTY04_CODE) {
    LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  sp=NULL; sq=NULL; sx=NULL; snu=NULL; skey=NULL;
  mkey = (kty04_mgr_key_t *) key->key;

  if(!(sp = bigz_get_str(10, mkey->p))) goto key_to_string_error;
  if(!(sq = bigz_get_str(10, mkey->q))) goto key_to_string_error;
  if(!(sx = bigz_get_str(10, mkey->x))) goto key_to_string_error;
  if(!(snu = misc_uint642string(mkey->nu))) goto key_to_string_error;

  length = strlen(sp)+strlen("p: \n")+strlen(sq)+strlen("q: \n")+
    strlen(sx)+strlen("x: \n")+strlen(snu)+strlen("nu: \n");

  if(!(skey = (char *) malloc(sizeof(char)*(length+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "kty04_mgr_key_to_string", __LINE__, 
		  errno, LOGERROR);
    goto key_to_string_error;
  }

  sprintf(skey, 
	  "p: %s\n"
	  "q: %s\n"
	  "x: %s\n"
	  "nu: %s\n\n",
	  sp, sq, sx, snu);

 key_to_string_error:

  free(sp); sp = NULL;
  free(sq); sq = NULL;
  free(sx); sx = NULL;
  free(snu); snu = NULL;

  return skey;

}

/* char* kty04_mgr_key_prv_to_string(groupsig_key_t *key) { */

/*   if(!key || key->scheme != GROUPSIG_KTY04_CODE) { */
/*     LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_prv_to_string", __LINE__, LOGERROR); */
/*     return NULL; */
/*   } */

/*   return kty04_mgr_key_to_string(key); */

/* } */

/* char* kty04_mgr_key_pub_to_string(groupsig_key_t *key) { */
  
/*   if(!key || key->scheme != GROUPSIG_KTY04_CODE) { */
/*     LOG_EINVAL(&logger, __FILE__, "kty04_mgr_key_pub_to_string", __LINE__, LOGERROR); */
/*     return NULL; */
/*   } */

/*   /\* The manager key does not have public part *\/ */
/*   return NULL; */

/* } */

/* mgr_key.c ends here */
