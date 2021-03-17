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
 * @file: mem_key.h
 * @brief: DL21 member keys.
 * @author: jesus
 * Maintainer: jesus
 * @date: mié may  9 17:11:58 2012 (+0200)
 * @version: 0.1
 * Last-Updated: vie ago 23 11:00:59 2013 (+0200)
 *           By: jesus
 *     Update #: 5
 * URL: bitbucket.org/jdiazvico/libgroupsig
 */

#ifndef _DL21_MEM_KEY_H
#define _DL21_MEM_KEY_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "dl21.h"
#include "include/mem_key.h"
#include "shim/pbc_ext.h"

/**
 * @def DL21_MEM_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing DL21 member keys
 */
#define DL21_MEM_KEY_BEGIN_MSG "BEGIN DL21 MEMBERKEY"

/**
 * @def DL21_MEM_KEY_END_MSG
 * @brief End string to prepend to headers of files containing DL21 member keys
 */
#define DL21_MEM_KEY_END_MSG "END DL21 MEMBERKEY"

/**
 * @struct dl21_mem_key_t
 * @brief DL21 member keys.
 */
typedef struct {
  pbcext_element_G1_t *A; /**< A = (H*h2^s*g1)^(1/isk+x) */
  pbcext_element_Fr_t *x; /**< Randomly picked by the Issuer. */
  pbcext_element_Fr_t *y; /**< Randomly picked by the Member. */
  pbcext_element_Fr_t *s; /**< Randomly picked by the Issuer. */
  /* pbcext_element_Fr_t *k; /\**< Randomly picked by the Member. *\/ */
  /* pbcext_element_Fr_t *kk; /\**< Randomly picked by the Member. *\/ */
  /* Precomputations */
  pbcext_element_G1_t *H; /**< Member's "public key". H = h1^y. */
  pbcext_element_G1_t *h2s; /**< Used in signatures. h2s = h2^s. */
} dl21_mem_key_t;

/** 
 * @fn groupsig_key_t* dl21_mem_key_init()
 * @brief Creates a new group key.
 *
 * @return A pointer to the initialized group key or NULL in case of error.
 */
groupsig_key_t* dl21_mem_key_init();

/** 
 * @fn int dl21_mem_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given member key.
 *
 * @param[in,out] key The member key to initialize.
 * 
 * @return IOK or IERROR
 */
int dl21_mem_key_free(groupsig_key_t *key);

/** 
 * @fn int dl21_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies the source key into the destination key (which must be initialized 
 *  by the caller).
 *
 * @param[in,out] dst The destination key.
 * @param[in] src The source key.
 * 
 * @return IOK or IERROR.
 */
int dl21_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/** 
 * @fn int dl21_mem_key_get_size_in_format(groupsig_key_t *key)
 * @brief Returns the size that the given key would require in order to be 
 *  represented as an array of bytes.
 *
 * @param[in] key The key.
 * 
 * @return The required number of bytes, or -1 if error.
 */
int dl21_mem_key_get_size(groupsig_key_t *key);

/** 
 * @fn int dl21_mem_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key)
 * @brief Writes a bytearray representation of the given member key to an array
 *  with format:
 *
 *  | DL21_CODE | KEYTYPE | size_A | A | size_x | x | 
 *    size_y | y | size_s | s | size_H | H | size_h2s | h2s |
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported
 *  member key. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] key The member key to export.
 * 
 * @return IOK or IERROR. 
 */
int dl21_mem_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* dl21_mem_key_import(byte_t *source, uint32_t size)
 * @brief Imports a member key.
 *
 * Imports a DL21 member key from the specified source, of the specified format.
 * 
 * @param[in] source The array of bytes containing the key to import.
 * @param[in] source The number of bytes in the passed array.
 * 
 * @return A pointer to the imported member key, or NULL if error.
 */
groupsig_key_t* dl21_mem_key_import(byte_t *source, uint32_t size);

/** 
 * @fn char* dl21_mem_key_to_string(groupsig_key_t *key)
 * @brief Gets a printable representation of the specified member key.
 *
 * @param[in] key The member key.
 * 
 * @return A pointer to the obtained string, or NULL if error.
 */
char* dl21_mem_key_to_string(groupsig_key_t *key);

/**
 * @var dl21_mem_key_handle
 * @brief Set of functions for managing DL21 member keys.
 */
static const mem_key_handle_t dl21_mem_key_handle = {
  .code = GROUPSIG_DL21_CODE, /**< The scheme code. */
  .init = &dl21_mem_key_init, /**< Initializes member keys. */
  .free = &dl21_mem_key_free, /**< Frees member keys. */
  .copy = &dl21_mem_key_copy, /**< Copies member keys. */
  .get_size = &dl21_mem_key_get_size, /**< Gets the size of the key as an array of bytes. */
  .gexport = &dl21_mem_key_export, /**< Exports member keys. */
  .gimport = &dl21_mem_key_import, /**< Imports member keys. */
  .to_string = &dl21_mem_key_to_string, /**< Converts member keys to printable strings. */
};

#endif /* _DL21_MEM_KEY_H */

/* mem_key.h ends here */
