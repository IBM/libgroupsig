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
 * @file: grp_key.h
 * @brief: DL21 group keys.
 * @author: jesus
 * Maintainer: jesus
 * @date: mié may  9 17:11:58 2012 (+0200)
 * @version: 0.1 
 * Last-Updated: vie ago 23 11:00:05 2013 (+0200)
 *           By: jesus
 *     Update #: 6
 * URL: bitbucket.org/jdiazvico/libgroupsig
 */

#ifndef _DL21_GRP_KEY_H
#define _DL21_GRP_KEY_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "dl21.h"
#include "include/grp_key.h"
#include "shim/pbc_ext.h"


/**
 * @struct dl21_grp_key_t
 * @brief Structure for DL21 group keys.
 *
 * For convenience, we set a public key of DL21 to contain the instance parameters 
 * as well as the public keys of Issuer and Converter. @TODO We may want to 
 * redesign this at some point...
 */
typedef struct {
  pbcext_element_G1_t *g1; /**< Params. Random generator of G1. */
  pbcext_element_G2_t *g2; /**< Params. Random generator of G2. */
  pbcext_element_G1_t *h1; /**< Params. Random generator of G1. */
  pbcext_element_G1_t *h2; /**< Params. Random generator of G1. */
  pbcext_element_G2_t *ipk; /**< Issuer public key. */
} dl21_grp_key_t;

/**
 * @def DL21_GRP_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing DL21 group keys
 */
#define DL21_GRP_KEY_BEGIN_MSG "BEGIN DL21 GROUPKEY"

/**
 * @def DL21_GRP_KEY_END_MSG
 * @brief End string to prepend to headers of files containing DL21 group keys
 */
#define DL21_GRP_KEY_END_MSG "END DL21 GROUPKEY"

/** 
 * @fn groupsig_key_t* dl21_grp_key_init()
 * @brief Creates a new group key.
 *
 * @return A pointer to the initialized group key or NULL in case of error.
 */
groupsig_key_t* dl21_grp_key_init();

/** 
 * @fn int dl21_grp_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given group key.
 *
 * @param[in,out] key The group key to initialize.
 * 
 * @return IOK or IERROR
 */
int dl21_grp_key_free(groupsig_key_t *key);

/** 
 * @fn int dl21_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies a group key.
 *
 * Copies the source key into the destination key (which must be initialized by 
 * the caller).
 *
 * @param[in,out] dst The destination key.
 * @param[in] src The source key.
 * 
 * @return IOK or IERROR.
 */
int dl21_grp_key_copy(groupsig_key_t *dst, groupsig_key_t *src);


/**
 * @fn int dl21_grp_key_get_size_in_format(groupsig_key_t *key)
 * @brief Returns the number of bytes required to export the key.
 *
 * @param[in] key The key.
 *
 * @return The required number of bytes, or -1 if error.
 */
int dl21_grp_key_get_size(groupsig_key_t *key);

/** 
 * @fn int dl21_grp_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key)
 * @brief Exports the given group key to a bytearray with the following format:
 *
 *  | DL21_CODE | KEYTYPE | size_g1 | g1 | size_g2 | g2 |
 *    size_h1 | h1 | size_h2 | h2 | size_ipk | ipk |
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported
 *  group key. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] key The group key to export.
 * 
 * @return IOK or IERROR.
 */
int dl21_grp_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* dl21_grp_key_import(byte_t *source, uint32_t size)
 * @brief Imports a group key.
 *
 * Imports a DL21 group key from the specified source, of the specified format.
 * 
 * @param[in] source The array of bytes containing the key to import.
 * @param[in] source The number of bytes in the passed array.
 * 
 * @return A pointer to the imported key, or NULL if error.
 */
groupsig_key_t* dl21_grp_key_import(byte_t *source, uint32_t size);

/** 
 * @fn char* dl21_grp_key_to_string(groupsig_key_t *key)
 * @brief Converts the key to a printable string.
 *
 * Returns a printable string associated to the given key.
 *
 * @param[in] key The key to convert.
 * 
 * @return The printable string associated to the key, or NULL if error.
 */
char* dl21_grp_key_to_string(groupsig_key_t *key);

/**
 * @var dl21_grp_key_handle
 * @brief The set of functions to manage DL21 group keys.
 */
static const grp_key_handle_t dl21_grp_key_handle = {
 .code = GROUPSIG_DL21_CODE, /**< Scheme. */
 .init = &dl21_grp_key_init, /**< Initialize group keys. */
 .free = &dl21_grp_key_free, /**< Free group keys. */
 .copy = &dl21_grp_key_copy, /**< Copy group keys. */
 .gexport = &dl21_grp_key_export, /**< Export group keys. */
 .gimport = &dl21_grp_key_import, /**< Import group keys. */
 .to_string = &dl21_grp_key_to_string, /**< Convert to printable strings. */
 .get_size = &dl21_grp_key_get_size, /**< Get size of key as bytes. */
};

#endif

/* grp_key.h ends here */
