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
#include <errno.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "prf.h"
#include "sys/mem.h"
#include "shim/hash.h"

#include "misc/misc.h"

prf_key_t* prf_key_init() {

  prf_key_t *key;
  
  if (!(key = (prf_key_t *) mem_malloc(sizeof(prf_key_t)))) {
    return NULL;
  }

  if(!(key->bytes = (byte_t *) mem_malloc(sizeof(byte_t)*HASH_BLAKE2_LENGTH))) {
    return NULL;
  }

  key->len = (uint8_t) HASH_BLAKE2_LENGTH;

  return key;
  
}

prf_key_t* prf_key_init_random() {

  prf_key_t *key;
  
  if (!(key = (prf_key_t *) mem_malloc(sizeof(prf_key_t)))) {
    return NULL;
  }

  if(!(key->bytes = (byte_t *) mem_malloc(sizeof(byte_t)*HASH_BLAKE2_LENGTH))) {
    return NULL;
  }
  
  key->len = (uint8_t) HASH_BLAKE2_LENGTH;

  /* Set bytes to random */
  if(RAND_bytes(key->bytes, key->len) != 1) {
    mem_free(key->bytes); key->bytes = NULL;
    mem_free(key); key = NULL;
  }
  
  return key;
  
}

int prf_key_free(prf_key_t *key) {

  if (!key) return IOK;

  if (key->bytes) { mem_free(key->bytes); key->bytes = NULL; }
  mem_free(key); key = NULL;

  return IOK;

}

int prf_compute(byte_t **out, uint64_t *outlen, prf_key_t *key,
		byte_t *data, uint64_t len) {

  const EVP_MD *md;
  HMAC_CTX *hmac_ctx;
  byte_t _out[EVP_MAX_MD_SIZE];
  unsigned int _len;

  if (!out || !outlen || !key || !data || !len) {
    LOG_EINVAL(&logger, __FILE__, "_dl20_compute_seq", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Initialize md */
  if(!(md = EVP_get_digestbyname(HASH_BLAKE2_NAME))) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "prf_compute", __LINE__, EDQUOT,
		      "OpenSSL: Unknown hash algorithm", LOGERROR);
    return IERROR;
  }

  /* Compute the HMAC */  
  if(!(hmac_ctx = HMAC_CTX_new())) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "prf_compute", __LINE__, EDQUOT,
		      "OpenSSL: HMAC_CTX_new", LOGERROR);
    return IERROR;
  }

  if(!(HMAC_Init_ex(hmac_ctx, key->bytes, key->len, md, NULL))) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "prf_compute", __LINE__, EDQUOT,
		      "OpenSSL: HMAC_Init_ex", LOGERROR);
    HMAC_CTX_free(hmac_ctx);	
    return IERROR;
  }

  if(!(HMAC_Update(hmac_ctx, data, (int) len))) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "prf_compute", __LINE__, EDQUOT,
		      "OpenSSL: HMAC_Update", LOGERROR);
    HMAC_CTX_free(hmac_ctx);
    return IERROR;
  }

  memset(_out, 0, EVP_MAX_MD_SIZE);
  if(!(HMAC_Final(hmac_ctx, _out, &_len))) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "prf_compute", __LINE__, EDQUOT,
		      "OpenSSL: HMAC_Final", LOGERROR);
    HMAC_CTX_free(hmac_ctx);
    return IERROR;
  }

  if (!*out) {
    if(!(*out = (byte_t *) mem_malloc(sizeof(byte_t)*_len))) {
      LOG_ERRORCODE(&logger, __FILE__, "prf_compute", __LINE__, errno, LOGERROR);
      return IERROR;
    }
    memcpy(*out, _out, _len);
  } else {
    memcpy(*out, _out, _len);
  }

  *outlen = (uint64_t) _len;
  HMAC_CTX_free(hmac_ctx);
  
  return IOK;
  
}
