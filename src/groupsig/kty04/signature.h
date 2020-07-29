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

#ifndef _KTY04_SIGNATURE_H
#define _KTY04_SIGNATURE_H

#include <stdint.h>
#include "include/signature.h"
#include "bigz.h"
#include "kty04.h"

/** @todo It will be a good improvement to make the scheme adaptable 
    to other relations. */

/**
 * @def KTY04_SIGNATURE_Z 
 * @brief Defines the number of relations in the KTY04 scheme.
 */
#define KTY04_SIGNATURE_Z 6

/**
 * @def KTY04_SIGNATURE_R 
 * @brief Defines the number of free variables in the KTY04 scheme.
 */
#define KTY04_SIGNATURE_R 5

/**
 * @def KTY04_SIGNATURE_M
 * @brief Defines the number of objects in the KTY04 scheme.
 */
#define KTY04_SIGNATURE_M 13

/**
 * @def KTY04_SUPPORTED_SIG_FORMATS_N
 * @brief Number of supported signature formats in KTY04.
 */
#define KTY04_SUPPORTED_SIG_FORMATS_N 6

/**
 * @var KTY04_SUPPORTED_SIG_FORMATS
 * @brief List of supported signature formats in KTY04.
 */
static const int KTY04_SUPPORTED_SIG_FORMATS[KTY04_SUPPORTED_SIG_FORMATS_N] = { 
  GROUPSIG_SIGNATURE_FORMAT_FILE_NULL,
  GROUPSIG_SIGNATURE_FORMAT_FILE_NULL_B64,
  GROUPSIG_SIGNATURE_FORMAT_BYTEARRAY,
  GROUPSIG_SIGNATURE_FORMAT_STRING_NULL_B64,
  GROUPSIG_SIGNATURE_FORMAT_MESSAGE_NULL,
  GROUPSIG_SIGNATURE_FORMAT_MESSAGE_NULL_B64,
};

/**
 * @struct kty04_signature_t
 * @brief Defines the structure of a KTY04 signature.
 */
typedef struct {
  uint8_t scheme; /**< Metainformation: the gs scheme this key belongs to. */
  bigz_t c; /**< The result of hash(message | B[1] | ... | B[z] | A[1] | ... | A[m]), 
	      where z is the number of relations, m the number of objects, and '|'
	      denotes concatenation. */
  bigz_t *A; /**< The A's. */
  /* mpz_t *B; /\**< The B's. *\/ */
  bigz_t *sw; /**< The sw's. */
  uint32_t m; /**< The number of elements in A. */
  uint32_t z; /**< The number of elements in B. */
  uint32_t r; /**< The number of elements in sw. */
} kty04_signature_t;

/** 
 * @fn groupsig_signature_t* kty04_signature_init()
 * @brief Initializes the fields of a KTY04 signature.
 * 
 * @return A pointer to the allocated signature, or NULL if error.
 */
groupsig_signature_t* kty04_signature_init();

/** 
 * @fn int kty04_signature_free(groupsig_signature_t *sig)
 * @brief Frees the alloc'ed fields of the given KTY04 signature.
 *
 * @param[in,out] sig The signature to free.
 * 
 * @return IOK or IERROR
 */
int kty04_signature_free(groupsig_signature_t *sig);

/** 
 * @fn int kty04_signature_copy(groupsig_signature_t *dst, 
 *                              groupsig_signature_t *src)
 * @brief Copies the given source signature into the destination signature.
 *
 * @param[in,out] dst The destination signature. Initialized by the caller.
 * @param[in] src The signature to copy. 
 * 
 * @return IOK or IERROR.
 */
int kty04_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src);

/** 
 * @fn int kty04_signature_to_string(groupsig_signature_t *sig)
 * @brief Returns a printable string representing the current signature.
 *
 * @param[in] sig The signature o convert.
 * 
 * @return A pointer to the created string or NULL if error.
 */
char* kty04_signature_to_string(groupsig_signature_t *sig);

/** 
 * @fn int kty04_signature_get_size_in_format(groupsig_signature_t *sig, 
 *   groupsig_signature_format_t format)
 * Returns the size of the signature in the specified format. Useful when you have
 * to export the signature and pre-allocate the destination.
 *
 * @param[in] sig The signature.
 * @param[in] format The format.
 * 
 * @return -1 if error, the size that this signature would have in case of
 *  being exported to the specified format.
 */
int kty04_signature_get_size_in_format(groupsig_signature_t *sig, 
				       groupsig_signature_format_t format);

/** 
 * @fn int kty04_signature_export(groupsig_signature *signature,
 *                                groupsig_signature_format_t format,
 *                                void *dst)
 * @brief Exports the specified signature to the given destination using
 *  the specified format..
 *
 * @param[in] signature The signature to export.
 * @param[in] format The format to use.
 * @param[in,out] dst Details about the destination. Will depend on the
 *  specified parameter.
 * 
 * @return IOK or IERROR
 */
int kty04_signature_export(groupsig_signature_t *signature, 
			   groupsig_signature_format_t format, 
			   void *dst);

/** 
 * @fn groupsig_signature_t* kty04_signature_import(kty04_groupsig_signature_format_t format, 
 *                                            void *source)
 * @brief Imports a signature according to the specified format.
 *
 * @param[in] format The format of the signature to import.
 * @param[in] source The signature to be imported.
 * 
 * @return A pointer to the imported signature.
 */
groupsig_signature_t* kty04_signature_import(groupsig_signature_format_t format, void *source);

/**
 * @var kty04_signature_handle
 * @brief Set of functions for managing KTY04 signatures.
 */
static const groupsig_signature_handle_t kty04_signature_handle = {
  GROUPSIG_KTY04_CODE, /**< The scheme code. */
  &kty04_signature_init,  /**< Initializes signatures. */
  &kty04_signature_free, /**< Frees signatures. */
  &kty04_signature_copy, /**< Copies signatures. */
  &kty04_signature_get_size_in_format, /**< Gets the size in bytes of a signature
					  in a specific format. */
  &kty04_signature_export, /**< Exports signatures. */
  &kty04_signature_import, /**< Imports signatures. */
  &kty04_signature_to_string, /**< Converts signatures to printable strings. */
};

#endif

/* signature.h ends here */
