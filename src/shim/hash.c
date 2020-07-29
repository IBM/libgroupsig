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

static hash_t* _hash_sha1(byte_t *bytes, uint32_t size) {

  hash_t *hash;
  byte_t *sha;

  if(!bytes || !size) {
    LOG_EINVAL(&logger, __FILE__, "_hash_sha1", __LINE__, LOGERROR);
    return NULL;
  }  

  if(!(sha = (byte_t *) mem_malloc(sizeof(byte_t)*SHA_DIGEST_LENGTH))) {
    LOG_ERRORCODE(&logger, __FILE__, "_hash_sha1", __LINE__, errno, LOGERROR);
    return NULL;
  }

  memset(sha, 0, SHA_DIGEST_LENGTH);
  SHA1(bytes, size, sha);

  if(!(hash = hash_init(HASH_SHA1))) {
    mem_free(sha); sha = NULL;
    LOG_ERRORCODE(&logger, __FILE__, "_hash_sha1", __LINE__, errno, LOGERROR);
    return NULL;
  }

  hash->length = SHA_DIGEST_LENGTH;
  hash->hash = sha;

  return hash;

}

hash_t* hash_init(uint8_t type) {

  hash_t *hash;
  
  if(!(hash = (hash_t *) mem_malloc(sizeof(hash_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "hash_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  hash->type = type;
  hash->hash = NULL;
  hash->length = 0;

  /* Set the object to a pointer to a openssl - SHA_CTX structure */
  if(!(hash->object = (SHA_CTX *) mem_malloc(sizeof(SHA_CTX)))) {
    LOG_ERRORCODE(&logger, __FILE__, "hash_init", __LINE__, errno, LOGERROR);
    hash_free(hash); hash = NULL;
    return NULL;
  }
  
  if(!SHA1_Init((SHA_CTX *) hash->object)) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "hash_init", __LINE__, EDQUOT,
		      "SHA1_Init", LOGERROR);
    hash_free(hash); hash = NULL;
    return NULL;
  }

  return hash;
  
}

int hash_free(hash_t *hash) {

  if(!hash) {
    LOG_EINVAL_MSG(&logger, __FILE__, "hash_free", __LINE__, 
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  mem_free(hash->hash); hash->hash = NULL;
  mem_free(hash->object); hash->object = NULL;
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

  switch(hash->type) {

  case HASH_SHA1:

    /* Update the created/received object */
    if(!SHA1_Update(hash->object, bytes, size)) {
      LOG_ERRORCODE_MSG(&logger, __FILE__, "hash_update", __LINE__, EDQUOT,
			"SHA1_Update", LOGERROR);
      return IERROR;
    }

    return IOK;

  default:
    LOG_EINVAL_MSG(&logger, __FILE__, "hash_update", __LINE__,
		   "Unexpected execution flow.", LOGERROR);
    return IERROR;
  }
  
  LOG_EINVAL_MSG(&logger, __FILE__, "hash_update", __LINE__,
		 "Unexpected execution flow.", LOGERROR);
  return IERROR; 

}

int hash_finalize(hash_t *hash) {

  if(!hash || !hash->object) {
    LOG_EINVAL(&logger, __FILE__, "hash_finalize", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!_is_supported_hash(hash->type)) {
    LOG_EINVAL_MSG(&logger, __FILE__, "hash_finalize", __LINE__, 
		   "Unsupported hash algorithm.", LOGERROR);
    return IERROR;
  }

  /* For now, we just use SHA1, this switch approach may be easy to handle while
     the number of supported schemes is not very large, otherwise, another approach
     should be taken... */

  switch(hash->type) {

  case HASH_SHA1:
    
    hash->length = SHA_DIGEST_LENGTH;    
    if(!(hash->hash = (byte_t *) mem_malloc(sizeof(byte_t)*hash->length))) {
      LOG_ERRORCODE(&logger, __FILE__, "hash_finalize", __LINE__, errno, LOGERROR);
      return IERROR;
    }

    if(!SHA1_Final(hash->hash, (SHA_CTX *) hash->object)) {
      LOG_ERRORCODE_MSG(&logger, __FILE__, "hash_finalize", __LINE__, EDQUOT,
			"SHA1_Update", LOGERROR);
      mem_free(hash->hash); hash->hash = NULL;
      return IERROR;      
    }

    break;

  default:

    LOG_EINVAL_MSG(&logger, __FILE__, "hash_finalize", __LINE__,
		   "Unexpected execution flow.", LOGERROR);
    return IERROR;    
  }

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
