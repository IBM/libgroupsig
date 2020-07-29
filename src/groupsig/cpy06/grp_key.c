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

#include "sysenv.h"
#include "sys/mem.h"
#include "misc/misc.h"
#include "exim.h"
#include "wrappers/base64.h"
#include "wrappers/pbc_ext.h"

#include "cpy06.h"
#include "groupsig/cpy06/grp_key.h"

/* This breaks encapsulation, but is needed to get the number of bits of
   the elements in the group. */
/* From $PBC/ecc/d_param.c */
struct d_param_s {
  mpz_t q;       // curve defined over F_q
  mpz_t n;       // has order n (= q - t + 1) in F_q
  mpz_t h;       // h * r = n, r is prime
  mpz_t r;
  mpz_t a, b;    // curve equation is y^2 = x^3 + ax + b
  int k;         // embedding degree
  mpz_t nk;      // order of curve over F_q^k
  mpz_t hk;      // hk * r^2 = nk
  mpz_t *coeff;  // coefficients of polynomial used to extend F_q by k/2
  mpz_t nqr;     // a quadratic nonresidue in F_q^d that lies in F_q
};

typedef struct d_param_s *d_param_ptr;

/* static (private) functions */

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
  cpy06_grp_key_t *key = (cpy06_grp_key_t*)obj->eximable;
  cpy06_sysenv = sysenv->data;

  bytes_params = NULL;
  if(pbcext_dump_param_bytes(&bytes_params, &size_params, cpy06_sysenv->param) == IERROR) {
    return IERROR;
  }

  size = element_length_in_bytes(key->g1)+element_length_in_bytes(key->g2)+
    element_length_in_bytes(key->q)+element_length_in_bytes(key->r)+
    element_length_in_bytes(key->w)+element_length_in_bytes(key->x)+
    element_length_in_bytes(key->y)+element_length_in_bytes(key->z)+
    sizeof(int)*9+size_params+2;

  return size;
}

/**
 * @fn static int _export_fd(exim_t* obj, FILE *fd)
 * @brief Writes a bytearray representation of the given exim object to a
 * file descriptor with format:
 *
 *  | CPY06_CODE | KEYTYPE | size_params | params | size_g1 | g1 | size_g2 | g2 |
 *    size_q | q | size_r | r | size_w | w | size_x | x | size_y | y | size_z | z |
 *
 * @param[in] key The key to export.
 * @param[in, out] fd An open filestream to write to.
 *
 * @return IOK or IERROR
 */
static int _export_fd(exim_t* obj, FILE *fd) {

  cpy06_sysenv_t *cpy06_sysenv;
  cpy06_grp_key_t *key;
  uint8_t code, type;

  if(!obj || !obj->eximable || !fd) {
    LOG_EINVAL(&logger, __FILE__, "_export_fd", __LINE__, LOGERROR);
    return IERROR;
  }
  
  key = (cpy06_grp_key_t*) obj->eximable;
  cpy06_sysenv = sysenv->data;

  /* Dump GROUPSIG_CPY06_CODE */
  code = GROUPSIG_CPY06_CODE;
  if(fwrite(&code, sizeof(byte_t), 1, fd) != 1) {
    return IERROR;
  }

  /* Dump key type */
  type = GROUPSIG_KEY_GRPKEY;
  if(fwrite(&type, sizeof(byte_t), 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "_export_fd", __LINE__,
		  errno, LOGERROR);
    return IERROR;
  }

  /* Dump params */
  if(pbcext_dump_param_fd(cpy06_sysenv->param, fd) == IERROR) {
    return IERROR;
  }

  /* Dump g1 */
  if(pbcext_dump_element_fd(key->g1, fd) == IERROR) {
    return IERROR;
  }

  /* Dump g2 */
  if(pbcext_dump_element_fd(key->g2, fd) == IERROR) {
    return IERROR;
  }

  /* Dump q */
  if(pbcext_dump_element_fd(key->q, fd) == IERROR) {
    return IERROR;
  }

  /* Dump r */
  if(pbcext_dump_element_fd(key->r, fd) == IERROR) {
    return IERROR;
  }

  /* Dump w */
  if(pbcext_dump_element_fd(key->w, fd) == IERROR) {
    return IERROR;
  }

  /* Dump x */
  if(pbcext_dump_element_fd(key->x, fd) == IERROR) {
    return IERROR;
  }

  /* Dump y */
  if(pbcext_dump_element_fd(key->y, fd) == IERROR) {
    return IERROR;
  }

  /* Dump z */
  if(pbcext_dump_element_fd(key->z, fd) == IERROR) {
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
  cpy06_grp_key_t *cpy06_key;
  cpy06_sysenv_t *cpy06_sysenv;
  byte_t scheme, type;

  if(!fd || !obj) {
    LOG_EINVAL(&logger, __FILE__, "_import_fd", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(key = cpy06_grp_key_init())) {
    return IERROR;
  }

  cpy06_key = key->key;

  /* First sizeof(int) bytes: scheme */
  if(fread(&scheme, sizeof(byte_t), 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "_import_fd", __LINE__,
		  errno, LOGERROR);
    cpy06_grp_key_free(key); key = NULL;
    return IERROR;
  }

  if(scheme != key->scheme) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_import_fd", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    cpy06_grp_key_free(key); key = NULL;
    return IERROR;
  }

  /* Next sizeof(int) bytes: key type */
  if(fread(&type, sizeof(byte_t), 1, fd) != 1) {
    LOG_ERRORCODE(&logger, __FILE__, "_import_fd", __LINE__,
		  errno, LOGERROR);
    cpy06_grp_key_free(key); key = NULL;
    return IERROR;
  }

  if(type != GROUPSIG_KEY_GRPKEY) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "_import_fd", __LINE__,
		      EDQUOT, "Unexpected key scheme.", LOGERROR);
    cpy06_grp_key_free(key); key = NULL;
    return IERROR;
  }


  /* Get the params if sysenv->data is uninitialized */
  if(!sysenv->data) {

    /* Copy the param and pairing to the CPY06 internal environment */
    /* By setting the environment, we avoid having to keep a copy of params
       and pairing in manager/member keys and signatures, crls, gmls... */
    if(!(cpy06_sysenv = (cpy06_sysenv_t *) mem_malloc(sizeof(cpy06_sysenv_t)))) {
      cpy06_grp_key_free(key); key = NULL;
      return IERROR;
    }

    if(pbcext_get_param_fd(cpy06_sysenv->param, fd) == IERROR) {
      cpy06_grp_key_free(key); key = NULL;
      return IERROR;
    }

    pairing_init_pbc_param(cpy06_sysenv->pairing, cpy06_sysenv->param);

    if(cpy06_sysenv_update(cpy06_sysenv) == IERROR) {
      cpy06_grp_key_free(key); key = NULL;
      pbc_param_clear(cpy06_sysenv->param);
      mem_free(cpy06_sysenv); cpy06_sysenv = NULL;
      return IERROR;
    }

  } else { /* Else, skip it */

    if (pbcext_skip_param_fd(fd) == IERROR) {
      cpy06_grp_key_free(key); key = NULL;
    }

    cpy06_sysenv = sysenv->data;

  }

  /* Get g1 */
  element_init_G1(cpy06_key->g1, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->g1, fd) == IERROR) {
    cpy06_grp_key_free(key); key = NULL;
    cpy06_sysenv_free();
    return IERROR;
  }

  /* Get g2 */
  element_init_G2(cpy06_key->g2, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->g2, fd) == IERROR) {
    cpy06_grp_key_free(key); key = NULL;
    cpy06_sysenv_free();
    return IERROR;
  }

  /* Get q */
  element_init_G1(cpy06_key->q, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->q, fd) == IERROR) {
    cpy06_grp_key_free(key); key = NULL;
    cpy06_sysenv_free();
    return IERROR;
  }

  /* Get r */
  element_init_G2(cpy06_key->r, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->r, fd) == IERROR) {
    cpy06_grp_key_free(key); key = NULL;
    cpy06_sysenv_free();
    return IERROR;
  }

  /* Get w */
  element_init_G2(cpy06_key->w, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->w, fd) == IERROR) {
    cpy06_grp_key_free(key); key = NULL;
    cpy06_sysenv_free();
    return IERROR;
  }

  /* Get x */
  element_init_G1(cpy06_key->x, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->x, fd) == IERROR) {
    cpy06_grp_key_free(key); key = NULL;
    cpy06_sysenv_free();
    return IERROR;
  }

  /* Get y */
  element_init_G1(cpy06_key->y, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->y, fd) == IERROR) {
    cpy06_grp_key_free(key); key = NULL;
    cpy06_sysenv_free();
    return IERROR;
  }

  /* Get z */
  element_init_G1(cpy06_key->z, cpy06_sysenv->pairing);
  if(pbcext_get_element_fd(cpy06_key->z, fd) == IERROR) {
    cpy06_grp_key_free(key); key = NULL;
    cpy06_sysenv_free();
    return IERROR;
  }

  /* Precomputations... */

  /* T5 = e(g1, W) */
  element_init_GT(cpy06_key->T5, cpy06_sysenv->pairing);
  element_pairing(cpy06_key->T5, cpy06_key->g1, cpy06_key->w);

  /* e2 = e(z,g2) */
  element_init_GT(cpy06_key->e2, cpy06_sysenv->pairing);
  element_pairing(cpy06_key->e2, cpy06_key->z, cpy06_key->g2);

  /* e3 = e(z,r) */
  element_init_GT(cpy06_key->e3, cpy06_sysenv->pairing);
  element_pairing(cpy06_key->e3, cpy06_key->z, cpy06_key->r);

  /* e4 = e(g1,g2) */
  element_init_GT(cpy06_key->e4, cpy06_sysenv->pairing);
  element_pairing(cpy06_key->e4, cpy06_key->g1, cpy06_key->g2);

  /* e5 = e(q,g2) */
  element_init_GT(cpy06_key->e5, cpy06_sysenv->pairing);
  element_pairing(cpy06_key->e5, cpy06_key->q, cpy06_key->g2);

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

groupsig_key_t* cpy06_grp_key_init() {

  groupsig_key_t *key;

  if(!(key = (groupsig_key_t *) mem_malloc(sizeof(groupsig_key_t)))) {
    return NULL;
  }

  if(!(key->key = (cpy06_grp_key_t *) mem_malloc(sizeof(cpy06_grp_key_t)))) {
    mem_free(key); key = NULL;
    return NULL;
  }

  key->scheme = GROUPSIG_CPY06_CODE;
  
  return key;
  
}

int cpy06_grp_key_free(groupsig_key_t *key) {

  cpy06_grp_key_t *cpy06_key;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_grp_key_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;  
  }

  if(key->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_grp_key_free", __LINE__, LOGERROR);
    return IERROR;	       
  }

  if(key->key) {

    cpy06_key = key->key;
    element_clear(cpy06_key->g1);
    element_clear(cpy06_key->g2);
    element_clear(cpy06_key->q);
    element_clear(cpy06_key->r);
    element_clear(cpy06_key->w);
    element_clear(cpy06_key->x);
    element_clear(cpy06_key->y);
    element_clear(cpy06_key->z);
    element_clear(cpy06_key->T5);
    element_clear(cpy06_key->e2);
    element_clear(cpy06_key->e3);
    element_clear(cpy06_key->e4);
    element_clear(cpy06_key->e5);
    mem_free(key->key);
    key->key = NULL;
  }

  mem_free(key);

  return IOK;

}

int cpy06_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  cpy06_grp_key_t *cpy06_dst, *cpy06_src;

  if(!dst || dst->scheme != GROUPSIG_CPY06_CODE ||
     !src || src->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_grp_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  cpy06_dst = dst->key;
  cpy06_src = src->key;

  /* Copy the elements */
  element_init_same_as(cpy06_dst->g1, cpy06_src->g1);
  element_set(cpy06_dst->g1, cpy06_src->g1);
  element_init_same_as(cpy06_dst->g2, cpy06_src->g2);
  element_set(cpy06_dst->g2, cpy06_src->g2);
  element_init_same_as(cpy06_dst->q, cpy06_src->q);
  element_set(cpy06_dst->q, cpy06_src->q);  
  element_init_same_as(cpy06_dst->r, cpy06_src->r);
  element_set(cpy06_dst->r, cpy06_src->r);
  element_init_same_as(cpy06_dst->w, cpy06_src->w);
  element_set(cpy06_dst->w, cpy06_src->w);
  element_init_same_as(cpy06_dst->x, cpy06_src->x);
  element_set(cpy06_dst->x, cpy06_src->x);    
  element_init_same_as(cpy06_dst->y, cpy06_src->y);
  element_set(cpy06_dst->y, cpy06_src->y);  
  element_init_same_as(cpy06_dst->z, cpy06_src->z);
  element_set(cpy06_dst->z, cpy06_src->z);
  element_init_same_as(cpy06_dst->T5, cpy06_src->T5);
  element_set(cpy06_dst->T5, cpy06_src->T5);
  element_init_same_as(cpy06_dst->e2, cpy06_src->e2);
  element_set(cpy06_dst->e2, cpy06_src->e2);
  element_init_same_as(cpy06_dst->e3, cpy06_src->e3);
  element_set(cpy06_dst->e3, cpy06_src->e3);
  element_init_same_as(cpy06_dst->e4, cpy06_src->e4);
  element_set(cpy06_dst->e4, cpy06_src->e4);
  element_init_same_as(cpy06_dst->e5, cpy06_src->e5);
  element_set(cpy06_dst->e5, cpy06_src->e5);

  return IOK;

}

int cpy06_grp_key_get_size_in_format(groupsig_key_t *key, groupsig_key_format_t format) {
  if(!key || key->scheme != GROUPSIG_CPY06_CODE ||
     !_is_supported_format(format)) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_grp_key_get_size_in_format", __LINE__, LOGERROR);
    return -1;
  }
  exim_t wrap = {key->key, &_exim_h };
  return exim_get_size_in_format(&wrap, format);

}

int cpy06_grp_key_export(groupsig_key_t *key, groupsig_key_format_t format, void *dst) {

  exim_t wrap;
  
  if(!key || key->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_grp_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_grp_key_export", __LINE__,
  		   "The specified format is not supported.", LOGERROR);
    return IERROR;
  }

  /* Apply the specified conversion */
  wrap.eximable = key->key;
  wrap.funcs = &_exim_h;
  return exim_export(&wrap, format, dst);
  
}

groupsig_key_t* cpy06_grp_key_import(groupsig_key_format_t format, void *source) {

  if(!source) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_grp_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  /* See if the current scheme supports the given format */
  if(!_is_supported_format(format)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_grp_key_import", __LINE__,
  		   "The specified format is not supported.", LOGERROR);
    return NULL;
  }

  /* Apply the specified conversion */
  exim_t wrap = {NULL, &_exim_h };
  if(exim_import(format, source, &wrap) == IOK){
    return wrap.eximable;
  }

  return NULL;

}

char* cpy06_grp_key_to_string(groupsig_key_t *key) { 

  struct stat buf;
  uint64_t len;
  size_t b;
  cpy06_grp_key_t *cpy06_key;
  cpy06_sysenv_t *cpy06_sysenv;
  FILE *fd;
  char *skey, *tmpnm, *pbc_str;

  if(!key) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_grp_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  cpy06_key = (cpy06_grp_key_t *) key->key;
  cpy06_sysenv = sysenv->data;

  /* Get the size of the key (determined by the q value of the PBC struct) */
  b = mpz_sizeinbase(((d_param_ptr) cpy06_sysenv->param->data)->q, 2);

  /* PBC only supports direct dumping of the PBC parameters to a file... 
     We'll dump them to a file and then read the file to a string...
     @todo Probably reading the fields directly would be better, although
     it would break encapsulation... */
  // @todo tmpnam is deprecated!!! use mkstemp instead
  if(!(tmpnm = tmpnam(NULL))) {
    LOG_ERRORCODE(&logger, __FILE__, "cpy06_grp_key_to_string", __LINE__, 
		  errno, LOGERROR);
    return NULL;
  }
  
  if(!(fd = fopen(tmpnm, "w"))) {
    LOG_ERRORCODE(&logger, __FILE__, "cpy06_grp_key_to_string", __LINE__, 
		  errno, LOGERROR);
    return NULL;
  }

  /* Dump the pbc params to fd */
  pbc_param_out_str(fd, cpy06_sysenv->param);
  fclose(fd); fd = NULL;

  if(stat(tmpnm, &buf) == -1) {
    LOG_ERRORCODE(&logger, __FILE__, "cpy06_grp_key_to_string", __LINE__, 
		  errno, LOGERROR);
    return NULL;    
  }

  len = buf.st_size+10+strlen("Group key:  bits\n");

  /* Read the file to a string */
  if(!(skey = (char *) 
       mem_malloc(sizeof(char)*(len+1)))) {
    LOG_ERRORCODE(&logger, __FILE__, "cpy06_grp_key_to_string", __LINE__, 
		  errno, LOGERROR);
    return NULL;        
  }

  sprintf(skey, "Group key: %ld bits\n", b);

  pbc_str = NULL;
  if(misc_read_file_to_string(tmpnm, (char **) &pbc_str, &len) == IERROR) {
    LOG_ERRORCODE(&logger, __FILE__, "cpy06_grp_key_to_string", __LINE__, 
		  errno, LOGERROR);
    return NULL;        
  }

  sprintf(&skey[strlen(skey)], "%s", pbc_str);
  mem_free(pbc_str); pbc_str = NULL;

  unlink(tmpnm);

  return skey;

}

/* grp_key.c ends here */
