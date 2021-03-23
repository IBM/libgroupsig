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

#ifndef _GS_HASH_H
#define _GS_HASH_H

#include <openssl/sha.h>
#include <stdint.h>

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

#endif /* _GS_HASH_H */

/* hash.h ends here */
