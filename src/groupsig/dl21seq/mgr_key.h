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
 * @file: mgr_key.h
 * @brief: DL21SEQ Manager keys.
 * @author: jesus
 * Maintainer: jesus
 * @date: mié may  9 17:11:58 2012 (+0200)
 * @version: 0.1
 * Last-Updated: vie ago 23 11:00:33 2013 (+0200)
 *           By: jesus
 *     Update #: 6
 * URL: bitbucket.org/jdiazvico/libgroupsig
 */

#ifndef _DL21SEQ_MGR_KEY_H
#define _DL21SEQ_MGR_KEY_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "dl21seq.h"
#include "include/mgr_key.h"
#include "shim/pbc_ext.h"

/**
 * @def DL21SEQ_MGR_KEY_BEGIN_MSG
 * @brief Begin string to prepend to headers of files containing DL21SEQ group keys
 */
#define DL21SEQ_MGR_KEY_BEGIN_MSG "BEGIN DL21SEQ MANAGERKEY"

/**
 * @def DL21SEQ_MGR_KEY_END_MSG
 * @brief End string to prepend to headers of files containing DL21SEQ group keys
 */
#define DL21SEQ_MGR_KEY_END_MSG "END DL21SEQ MANAGERKEY"

/**
 * @struct dl21seq_mgr_key_t
 * @brief DL21SEQ Manager key.
 * 
 * The secret key for the issuing authority.
 */
typedef struct {
  pbcext_element_Fr_t *isk; /**< Issuer secret key. */
} dl21seq_mgr_key_t;

/** 
 * @fn groupsig_key_t* dl21seq_mgr_key_init()
 * @brief Creates a new DL21SEQ manager key
 *
 * @return The created manager key or NULL if error.
 */
groupsig_key_t* dl21seq_mgr_key_init();

/** 
 * @fn int dl21seq_mgr_key_free(groupsig_key_t *key)
 * @brief Frees the variables of the given manager key.
 *
 * @param[in,out] key The manager key to initialize.
 * 
 * @return IOK or IERROR
 */
int dl21seq_mgr_key_free(groupsig_key_t *key);

/** 
 * @fn int dl21seq_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src)
 * @brief Copies the source key into the destination key (which must be initialized by 
 * the caller).
 *
 * @param[in,out] dst The destination key.
 * @param[in] src The source key.
 * 
 * @return IOK or IERROR.
 */
int dl21seq_mgr_key_copy(groupsig_key_t *dst, groupsig_key_t *src);

/** 
 * @fn int dl21seq_mgr_key_get_size_in_format(groupsig_key_t *key)
 * @brief Returns the size that the given key would require as an array of bytes.
 *
 * @param[in] key The key.
 *
 * @return The required number of bytes, or -1 if error.
 */
int dl21seq_mgr_key_get_size(groupsig_key_t *key);

/** 
 * @fn int dl21seq_mgr_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key)
 * @brief Writes a bytearray representation of the given manager key to an array
 *  with format:
 *
 *  | DL21SEQ_CODE | KEYTYPE | size_isk | isk |
 *
 * @param[in,out] bytes A pointer to the array that will contain the exported
 *  manager key. If <i>*bytes</i> is NULL, memory will be internally allocated.
 * @param[in,out] size Will be set to the number of bytes written in <i>*bytes</i>.
 * @param[in] key The manager key to export.
 * 
 * @return IOK or IERROR.
 */
int dl21seq_mgr_key_export(byte_t **bytes, uint32_t *size, groupsig_key_t *key);

/** 
 * @fn groupsig_key_t* dl21seq_mgr_key_import(byte_t *source, uint32_t size)
 * @brief Imports a DL21 manager key from the specified source.
 *
 * @param[in] source The array of bytes containing the key to import.
 * @param[in] source The number of bytes in the passed array.
 * 
 * @return A pointer to the imported manager key, or NULL if error.
 */
groupsig_key_t* dl21seq_mgr_key_import(byte_t *source, uint32_t size);

/** 
 * @fn char* dl21seq_mgr_key_to_string(mgr_key_t *key)
 * @brief Creates a printable string of the given manager key.
 *
 * @param[in] key The manager key.
 * 
 * @return The created string or NULL if error.
 */
char* dl21seq_mgr_key_to_string(groupsig_key_t *key);

/**
 * @var dl21seq_mgr_key_handle
 * @brief Set of functions for DL21SEQ manager keys management.
 */
static const mgr_key_handle_t dl21seq_mgr_key_handle = {
  .code = GROUPSIG_DL21SEQ_CODE, /**< The scheme code. */
  .init = &dl21seq_mgr_key_init, /**< Initializes manager keys. */
  .free = &dl21seq_mgr_key_free, /**< Frees manager keys. */
  .copy = &dl21seq_mgr_key_copy, /**< Copies manager keys. */
  .gexport = &dl21seq_mgr_key_export, /**< Exports manager keys. */
  .gimport = &dl21seq_mgr_key_import, /**< Imports manager keys. */
  .to_string = &dl21seq_mgr_key_to_string, /**< Converts manager keys to printable strings. */
  .get_size &dl21seq_mgr_key_get_size /**< Gets the size of the key, in bytes. */
};

#endif

/* mgr_key.h ends here */
