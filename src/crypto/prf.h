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
 * @file: hash.h
 * @brief: Wrapper for hash functions
 *
 * Currently, the internal library for hashes is libssl (openssl)
 *
 * @author: jesus
 * Maintainer: jesus
 * @date: mié may  9 17:11:58 2012 (+0200)
 * @version: 0.1
 * Last-Updated: mar oct  8 22:02:14 2013 (+0200)
 *           By: jesus
 *     Update #: 12
 * URL: bitbucket.org/jdiazvico/libgroupsig
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
