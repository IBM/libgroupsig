/*                               -*- Mode: C -*- 
 *
 *	libgroupsig Group Signatures library
 *	Copyright (C) 2012-2013 Jesus Diaz Vico
 *
 *		
 *
 *	This file is part of the libgroupsig Group Signatures library.
 *
 *
 *  The libgroupsig library is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License as 
 *  defined by the Free Software Foundation, either version 3 of the License, 
 *  or any later version.
 *
 *  The libroupsig library is distributed WITHOUT ANY WARRANTY; without even 
 *  the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
 *  See the GNU Lesser General Public License for more details.
 *
 *
 *  You should have received a copy of the GNU Lesser General Public License 
 *  along with Group Signature Crypto Library.  If not, see <http://www.gnu.org/
 *  licenses/>
 *
 * @file: hash.c
 * @brief: 
 * @author: jesus
 * Maintainer: 
 * @date: jue jul  5 14:42:56 2012 (+0200)
 * @version: 
 * Last-Updated: mar oct  8 22:01:57 2013 (+0200)
 *           By: jesus
 *     Update #: 41
 * URL: https://bitbucket.org/jdiazvico/libgroupsig
 */

#include <openssl/evp.h>

#include "logger.h"
#include "hash.h"
#include "sys/mem.h"
#include "misc/misc.h"

/** @todo Everywhere! Use EVP_* instead of SHA1_* */

static uint8_t _is_supported_hash(uint8_t type) {

  int i;

  for(i=0; i<HASH_SUPPORTED_HASHES_N; i++) {
    if(type == HASH_SUPPORTED_HASHES[i]) return 1;
  }

  return 0;

}

static char* _get_name_by_code(uint8_t type) {

  int i;

  for(i=0; i<HASH_SUPPORTED_HASHES_N; i++) {
    if(type == HASH_SUPPORTED_HASHES[i])
      return (char *) HASH_NAMES[i];
  }

  return NULL;
  
}

static hash_t* _hash_sha1(byte_t *bytes, uint32_t size) {

  hash_t *hash;
  int _size;

  if(!bytes || !size) {
    LOG_EINVAL(&logger, __FILE__, "_hash_sha1", __LINE__, LOGERROR);
    return NULL;
  }

  if(!(hash = hash_init(HASH_SHA1))) {
    LOG_ERRORCODE(&logger, __FILE__, "_hash_sha1", __LINE__, errno, LOGERROR);
    return NULL;
  }
  
  EVP_DigestUpdate(hash->mdctx, bytes, size);

  _size = EVP_MD_size(hash->md);
  if(!(hash->hash = (byte_t *) mem_malloc(sizeof(byte_t)*_size))) {
    LOG_ERRORCODE(&logger, __FILE__, "_hash_sha1", __LINE__, errno, LOGERROR);
    return NULL;
  }  
  
  EVP_DigestFinal_ex(hash->mdctx, hash->hash, &hash->length);
  
  return hash;

}

static hash_t* _hash_blake2(byte_t *bytes, uint32_t size) {

  hash_t *hash;
  int _size;

  if(!bytes || !size) {
    LOG_EINVAL(&logger, __FILE__, "_hash_blake2", __LINE__, LOGERROR);
    return NULL;
  }

  if(!(hash = hash_init(HASH_BLAKE2))) {
    LOG_ERRORCODE(&logger, __FILE__, "_hash_blake2", __LINE__, errno, LOGERROR);
    return NULL;
  }
  
  EVP_DigestUpdate(hash->mdctx, bytes, size);

  _size = EVP_MD_size(hash->md);
  if(!(hash->hash = (byte_t *) mem_malloc(sizeof(byte_t)*_size))) {
    LOG_ERRORCODE(&logger, __FILE__, "_hash_blake2", __LINE__, errno, LOGERROR);
    return NULL;
  }  
  
  EVP_DigestFinal_ex(hash->mdctx, hash->hash, &hash->length);
  
  return hash;

}

hash_t* hash_init(uint8_t type) {

  hash_t *hash;
  char *name;
  
  if(!(hash = (hash_t *) mem_malloc(sizeof(hash_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "hash_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  hash->type = type;
  hash->hash = NULL;
  hash->length = 0;

  if(!(name = _get_name_by_code(type))) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "hash_init", __LINE__, EDQUOT,
		      "Unknown hash algorithm", LOGERROR);
    return NULL;
  }

  /* Set OpenSSL's MD object */
  if(!(hash->md = (EVP_MD *) EVP_get_digestbyname(name))) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "hash_init", __LINE__, EDQUOT,
		      "OpenSSL: Unknown hash algorithm", LOGERROR);
    return NULL;
  }

  /* Initialize the CTX object */
  hash->mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(hash->mdctx, hash->md, NULL);

  return hash;
  
}

int hash_free(hash_t *hash) {

  if(!hash) {
    LOG_EINVAL_MSG(&logger, __FILE__, "hash_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  mem_free(hash->hash); hash->hash = NULL;
  EVP_MD_CTX_free(hash->mdctx); hash->mdctx = NULL;
  mem_free(hash);

  return IOK;

}

hash_t* hash_get(uint8_t type, byte_t *bytes, uint32_t size) {

  if(!bytes || !size) {
    LOG_EINVAL(&logger, __FILE__, "hash_get", __LINE__, LOGERROR);
    return NULL;
  }

  if(!_is_supported_hash(type)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "hash_get", __LINE__, 
		   "Unsupported hash algorithm.", LOGERROR);
    return NULL;
  }

  /* For now, we just use SHA1, this switch approach may be easy to handle while
     the number of supported schemes is not very large, otherwise, another approach
     should be taken... */
  
  switch(type) {
  case HASH_SHA1:
    return _hash_sha1(bytes, size);
  case HASH_BLAKE2:
    return _hash_blake2(bytes, size);
  default:
    LOG_EINVAL_MSG(&logger, __FILE__, "hash_get", __LINE__,
		   "Unexpected execution flow.", LOGERROR);
    return NULL;
  }
  
  LOG_EINVAL_MSG(&logger, __FILE__, "hash_get", __LINE__,
		 "Unexpected execution flow.", LOGERROR);
  return NULL;

}

int hash_update(hash_t *hash, byte_t *bytes, uint32_t size) {

  if(!hash || !bytes || !size) {
    LOG_EINVAL(&logger, __FILE__, "hash_update", __LINE__, LOGERROR);
    return IERROR;
  }

  EVP_DigestUpdate(hash->mdctx, bytes, size);

  return IOK;
  
}

int hash_finalize(hash_t *hash) {

  int size;
  
  if(!hash) {
    LOG_EINVAL(&logger, __FILE__, "hash_finalize", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!_is_supported_hash(hash->type)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "hash_finalize", __LINE__, 
		   "Unsupported hash algorithm.", LOGERROR);
    return IERROR;
  }

  size = EVP_MD_size(hash->md);
  if(!(hash->hash = (byte_t *) mem_malloc(sizeof(byte_t)*size))) {
    LOG_ERRORCODE(&logger, __FILE__, "hash_finalize", __LINE__, errno, LOGERROR);
    return IERROR;
  }

  EVP_DigestFinal_ex(hash->mdctx, hash->hash, &hash->length);

  return IOK;
  
}

int hash_get_hex(char **s, hash_t *hash) {

  if(!s || !hash) {
    LOG_EINVAL(&logger, __FILE__, "hash_get_hex", __LINE__, LOGERROR);
    return IERROR;
  }

  return misc_get_hex_representation(s, hash->hash, hash->length);

}

/* hash.c ends here */
