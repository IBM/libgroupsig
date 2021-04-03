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

#ifndef _GS_PRF_H
#define _GS_PRF_H

#include "types.h"
#include "logger.h"
#include "shim/pbc_ext.h"

#ifdef __cplusplus
extern "C" {
#endif


/* 
 * For now, this only implements the HMAC PRF [1]. If we need to add other PRFs,
 * consider creating an actual module. Right now, export/import of the keys
 * required by this PRF needs to be done by the schemes themselves. If this
 * becomes a module, it would be necessary to exim-ize this.
 *
 * [1] Mihir Bellare, Ran Canetti, Hugo Krawczyk:
 * Keying Hash Functions for Message Authentication. CRYPTO 1996: 1-15
 */

/**
 * @struct prf_key_t
 * @brief Data structure for HMAC PRF keys
 */
typedef struct {
  byte_t *bytes; /**< Raw key bytes. */
  uint8_t len; /**< Key length. */
} prf_key_t;

/**
 * @fn prf_key_t* prf_key_init();
 * @brief Initializes an HMAC PRF key.
 *
 * @return A pointer to the initialized PRF key or NULL if error.. 
 */
prf_key_t* prf_key_init();

/**
 * @fn prf_key_t* prf_key_init_random();
 * @brief Initializes a HMAC PRF key and randomly sets its internal variables.
 *
 * @return A pointer to the initialized PRF key or NULL if error.. 
 */
prf_key_t* prf_key_init_random();

/**
 * @fn int prf_key_free(prf_key_t *key);
 * @brief Frees the memory allocated for key.
 *
 * @param[in] k The PRF key to free.
 *
 * @return IOK or IERROR.
 */
int prf_key_free(prf_key_t *key);

/**
 * @fn int prf_compute(byte_t **out, uint64_t *outlen,
 *                     prf_key_t *key, byte_t *data, uint64_t len);
 * @brief Applies the HMAC PRF to data.
 *
 * @param[in,out] out The output produced by the PRF. If *out is
 *  NULL, memory will be internally allocated.
 * @param[in,out] outlen The length in bytes of the produced output.
 * @param[in] key The PRF key.
 * @param[in] data The array of bytes to use as seed
 * @param[in] len The length of data, in bytes.
 * 
 * @return IOK or IERROR. 
 */
int prf_compute(byte_t **out, uint64_t *outlen,
		prf_key_t *key, byte_t *data, uint64_t len);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _GS_SPK_H */
