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

#ifndef _KTY04_CRL_H
#define _KTY04_CRL_H

#include <stdint.h>
#include "types.h"
#include "sysenv.h"
#include "include/crl.h"
#include "bigz.h"
#include "groupsig/kty04/identity.h"

/**
 * @def KTY04_SUPPORTED_CRL_FORMATS_N
 * @brief Number of supported CRL formats in KTY04.
 */
#define KTY04_SUPPORTED_CRL_FORMATS_N 1

/**
 * @var KTY04_SUPPORTED_CRL_FORMATS
 * @brief List of formast supported by KTY04.
 */
static const int KTY04_SUPPORTED_CRL_FORMATS[KTY04_SUPPORTED_CRL_FORMATS_N] = {
  CRL_FILE,
};

/**
 * @struct kty04_crl_entry_t 
 * @brief CRL entries for KYT04.
 */
typedef struct {
  identity_t *id; /**< The user identity. */
  bigz_t trapdoor; /**<  The tracing trapdoor for this user. */
} kty04_crl_entry_t;

/* Entry public functions */

/**
 * @fn kty04_crl_entry_t* kty04_crl_entry_init()
 * @brief Creates a new CRL entry and initializes its fields.
 *
 * @return The created crl entry or NULL if error.
 */
kty04_crl_entry_t* kty04_crl_entry_init();

/**
 * @fn int kty04_crl_entry_free(kty04_crl_entry_t *entry)
 * @brief Frees the fields of the given CRL entry.
 *
 * @param[in,out] entry The CRL entry to free.
 *
 * @return IOK or IERROR
 */
int kty04_crl_entry_free(kty04_crl_entry_t *entry);

/** 
 * @fn char* kty04_crl_entry_to_string(kty04_crl_entry_t *entry)
 * Converts the received KTY04 CRL entry to a printable string.
 *
 * @param[in] entry The CRL entry.
 * 
 * @return The converted string or NULL if error.
 */
char* kty04_crl_entry_to_string(kty04_crl_entry_t *entry);

/* List public functions */

/** 
 * @fn crl_t* kty04_crl_init()
 * Initializes a CRL structure.
 *
 * @return A pointer to the initialized structure.
 */
crl_t* kty04_crl_init();

/** 
 * @fn int kty04_crl_free(crl_t *crl)
 * Frees the received CRL structure. Note that it does not free the entries.
 * If memory has been allocated for them, the caller must free it.
 *
 * @param[in,out] crl The CRL to free.
 * 
 * @return IOK.
 */
int kty04_crl_free(crl_t *crl);

/** 
 * @fn int kty04_crl_insert(crl_t *crl, void *entry)
 * Inserts the given entry into the crl. The memory pointed by the new entry is
 * not duplicated.
 *
 * @param[in,out] crl The CRL.
 * @param[in] entry The entry to insert.
 * 
 * @return IOK or IERROR with errno updated.
 */
int kty04_crl_insert(crl_t *crl, void *entry);

/** 
 * @fn int kty04_crl_remove(crl_t *crl, uint64_t index)
 * Removes the entry at position <i>index</i> from the CRL. The caller is 
 * responsible for removing the contents of the entry itself.
 *
 * @param[in,out] crl The CRL.
 * @param[in] index The index of the entry to remove.
 * 
 * @return IOK or IERROR with errno updated.
 */
int kty04_crl_remove(crl_t *crl, uint64_t index);

/** 
 * @fn void* kty04_crl_get(crl_t *crl, uint64_t index)
 * Returns a pointer to the CRL entry at the specified position.
 *
 * @param[in] crl The CRL.
 * @param[in] index The index of the entry to retrieve.
 * 
 * @return A pointer to the specified entry or NULL if error.
 */
void* kty04_crl_get(crl_t *crl, uint64_t index);

/**
 * @fn crl_t* kty04_crl_import(crl_type_t type, void *src)
 * @brief Loads the Group Members List stored in the given source, of the
 *  specified type, and returns a initialized CRL structure.
 *
 * @param[in] type The type of source.
 * @param[in] src The element containing the crl.
 *
 * @return The imported CRL or NULL if error.
 */
crl_t* kty04_crl_import(crl_format_t type, void *src);

/**
 * @fn int kty04_crl_export(crl_t *crl, void *dst, crl_format_t format)
 * @brief Exports the given Group Members List structure into the given destination.
 *
 * @param[in] crl The CRL structure to save.
 * @param[in] dst The destination.
 * @param[in] format The type of destination.
 *
 * @return IOK or IERROR
 */
int kty04_crl_export(crl_t *crl, void *dst, crl_format_t format);

/** 
 * @fn int kty04_crl_entry_cmp_id(void *entry1, void *entry2)
 * Compares the ID fields of two kty04_crl_entry_t structures. 
 *
 * @param[in] entry1 The first operand.
 * @param[in] entry2 The second operand.
 * 
 * @return 0 if both entries have the same ID, != 0 if not. If an error
 *  occurs, errno is updated.
 */
int kty04_crl_entry_cmp_id(void *entry1, void *entry2);

/** 
 * @fn int kty04_crl_entry_cmp_trapdoors(void *entry1, void *entry2)
 * Compares the trapdoor fields of two kty04_crl_entry_t structures. 
 *
 * @param[in] entry1 The first operand.
 * @param[in] entry2 The second operand.
 * 
 * @return 0 if both entries have the same trapdoor, != 0 if not. If an error
 *  occurs, errno is updated.
 */
int kty04_crl_entry_cmp_trapdoors(void *entry1, void *entry2);


/** 
 * @fn int kty04_crl_entry_exists(crl_t *crl, void *entry)
 * Returns 0 if there is no entry with the same trapdoor, 1 if there is.
 *
 * @param[in] crl The CRL.
 * @param[in] entry The entry to check.
 * 
 * @return 1 if the entry exists, 0 if not. On error, errno is updated.
 */
int kty04_crl_entry_exists(crl_t *crl, void *entry);

/** 
 * @fn int kty04_crl_trapdoor_exists(crl_t *crl, trapdoor_t *trap)
 * Returns 0 if there is no entry with the same trapdoor, 1 if there is.
 *
 * @param[in] crl The CRL
 * @param[in] trap The trapdoor.
 * 
 * @return 1 if the trapdoor exists, 0 if not. On error, errno is updated.
 */
int kty04_crl_trapdoor_exists(crl_t *crl, trapdoor_t *trap);

/**
 * @var kty04_crl_handle
 * @brief The set of functions for managing KTY04 CRLs.
 */
static const crl_handle_t kty04_crl_handle = {
  GROUPSIG_KTY04_CODE, /**< Handle code. */
  &kty04_crl_init, /**< Initialization function. */
  &kty04_crl_free, /**< Free function. */
  &kty04_crl_insert, /**< Insert a new entry. */
  &kty04_crl_remove, /**< Remove a specific entry. */
  &kty04_crl_get, /**< Get an specific entry (without removing). */
  &kty04_crl_import, /**< Import from an external source. */
  &kty04_crl_export, /**< Export to an external source. */
  &kty04_crl_entry_exists, /**< Test if a specific entry already exists
			      in the CRL. */
  &kty04_crl_trapdoor_exists, /**< Test if a specific trapdoor already
				 exists in the CRL. */
};

#endif /* _KTY04_CRL_H */

/* crl.h ends here */
