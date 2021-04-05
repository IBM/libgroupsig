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

#ifndef _GS_HASH_H
#define _GS_HASH_H

#include <openssl/sha.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
  
#include "types.h"

#define HASH_SUPPORTED_HASHES_N 2

#define HASH_SHA1 0
#define HASH_BLAKE2 1

#define HASH_SHA1_NAME "sha1"
#define HASH_BLAKE2_NAME "blake2s256"

#define HASH_SHA1_LENGTH 20
#define HASH_BLAKE2_LENGTH 32

static const int HASH_SUPPORTED_HASHES[HASH_SUPPORTED_HASHES_N] = {
  HASH_SHA1,
  HASH_BLAKE2,
};

static const char* HASH_NAMES[HASH_SUPPORTED_HASHES_N] = {
							  HASH_SHA1_NAME,
							  HASH_BLAKE2_NAME
};

typedef struct _hash_t {
  uint8_t type; /**< Type of hash. */
  unsigned int length;  /**< Number of bytes in the hash byte array. */
  byte_t *hash;  /**< Will be updated with the obtained hash. */
  void *mdctx;  /**< CTX object of OpenSSL. */
  void *md;  /**< MD object of OpenSSL. */
} hash_t;

/** 
 * @fn hash_t* hash_init(uint8_t type)
 * Initializes a hash structure.
 *
 * @param[in] type The type of hash that this structure will contain.
 * 
 * @return A pointer to the initialized structure.
 */
hash_t* hash_init(uint8_t type);

/** 
 * @fn byte_t* hash_get(uint8_t type, byte_t *bytes, uint32_t size)
 * Returns the hash of the given type associated to the received sequence of bytes.
 *
 * @param[in] The type of hash (one of HASH_SUPPORTED_TYPES)
 * @param[in] bytes The bytes to hash.
 * @param[in] size The number of bytes to hash.
 * 
 * @return A pointer to the generated hash or NULL if error.
 */
hash_t* hash_get(uint8_t type, byte_t *bytes, uint32_t size);

/** 
 * @fn int hash_update(hash_t *hash, byte_t *bytes, uint32_t size)
 * Updates the data to hash contained within the structure pointed to by <i>hash</i>.  
 * To obtain the hash associated to the "pushed" data, use hash_finalize(..).
 *
 * @param[in,out] hash The hash structure to update. 
 * @param[in] bytes The bytes to push into the hash.
 * @param[in] size The size of the bytes to push. 
 *
 * @return IOR or IERROR.
 */
int hash_update(hash_t *hash, byte_t *bytes, uint32_t size);

/** 
 * @fn int hash_finalize(hash_t *hash)
 * Computes the hash associated to the hash object in the received hash structure.
 * The <i>hash</i> and <i>length</i> attributes are set accordingly.
 *
 * @param[in,out] hash The hash structure containing the information to hash.
 * 
 * @return IOK or IERROR.
 */
int hash_finalize(hash_t *hash);

/** 
 * @fn int hash_free(hash_t *hash)
 * Frees the given hash structure.
 *
 * @param[in,out] hash The hash structure to free.
 * 
 * @return IOK.
 */
int hash_free(hash_t *hash);

/** 
 * @fn int hash_get_hex(char **s, hash_t *hash)
 * @brief Returns a hexadecimal representation of the given hash object.
 *
 * @param[in,out] A pointer to the hexadecimal representation of the given hash, or
 *  NULL if error.
 * @param[in] hash The hash to convert.
 * 
 * @return IOK or IERROR.
 */
int hash_get_hex(char **s, hash_t *hash);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _GS_HASH_H */

/* hash.h ends here */
