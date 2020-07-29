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

#ifndef _KTY04_GML_H
#define _KTY04_GML_H

#include "types.h"
#include "sysenv.h"
#include "include/gml.h"
#include "include/trapdoor.h"
#include "groupsig/kty04/identity.h"
#include "kty04.h"

/**
 * @def KTY04_SUPPORTED_GML_FORMATS_N
 * @brief Number GML formats supported by KTY04.
 */
#define KTY04_SUPPORTED_GML_FORMATS_N 1

/**
 * @var KTY04_SUPPORTED_GML_FORMATS
 * @brief List of GML formats supported by KTY04. 
 */
static const int KTY04_SUPPORTED_GML_FORMATS[KTY04_SUPPORTED_GML_FORMATS_N] = {
  GML_FILE,
};

/** 
 * @struct kty04_gml_entry_t
 * @brief Structure for KTY04 GML entries.
 */
typedef struct {
  identity_t *id; /**< Member's ID. */
  trapdoor_t *trapdoor; /**< Member's trapdoor. */
  bigz_t A; /**< A field computed by the Manager during manager_join. */
} kty04_gml_entry_t;

/* Entry public functions */

/**
 * @fn kty04_gml_entry_t* kty04_gml_entry_init()
 * @brief Creates a new GML entry and initializes its fields.
 *
 * @return The created gml entry or NULL if error.
 */
kty04_gml_entry_t* kty04_gml_entry_init();

/**
 * @fn int kty04_gml_entry_free(kty04_gml_entry_t *entry)
 * @brief Frees the fields of the given GML entry.
 *
 * @param[in,out] entry The GML entry to free.
 *
 * @return IOK or IERROR
 */
int kty04_gml_entry_free(kty04_gml_entry_t *entry);

/** 
 * @fn char* kty04_gml_entry_to_string(kty04_gml_entry_t *entry)
 * @brief Converts the received KTY04 GML entry to a printable string.
 *
 * @param[in] entry The GML entry.
 * 
 * @return The converted string or NULL if error.
 */
char* kty04_gml_entry_to_string(kty04_gml_entry_t *entry);

/* List public functions */

/** 
 * @fn gml_t* kty04_gml_init()
 * @brief Initializes a GML structure.
 * 
 * @return A pointer to the initialized structure.
 */
gml_t* kty04_gml_init();

/** 
 * @fn int kty04_gml_free(gml_t *gml)
 * @brief Frees the received GML structure. 
 *
 * Note that it does not free the entries. If memory has been allocated for 
 * them, the caller must free it.
 *
 * @param[in,out] gml The GML to free.
 * 
 * @return IOK.
 */
int kty04_gml_free(gml_t *gml);

/** 
 * @fn int kty04_gml_insert(gml_t *gml, void *entry)
 * @brief Inserts the given entry into the gml. The memory pointed by the new entry is
 * not duplicated.
 *
 * @param[in,out] gml The GML.
 * @param[in] entry The entry to insert.
 * 
 * @return IOK or IERROR with errno updated.
 */
int kty04_gml_insert(gml_t *gml, void *entry);

/** 
 * @fn int kty04_gml_remove(gml_t *gml, uint64_t index)
 * @brief Removes the entry at position <i>index</i> from the GML. The caller is 
 * responsible for removing the contents of the entry itself.
 *
 * @param[in,out] gml The GML.
 * @param[in] index The index of the entry to remove.
 * 
 * @return IOK or IERROR with errno updated.
 */
int kty04_gml_remove(gml_t *gml, uint64_t index);

/** 
 * @fn void* kty04_gml_get(gml_t *gml, uint64_t index)
 * @brief Returns a pointer to the GML entry at the specified position.
 *
 * @param[in] gml The GML.
 * @param[in] index The index of the entry to retrieve.
 * 
 * @return A pointer to the specified entry or NULL if error.
 */
void* kty04_gml_get(gml_t *gml, uint64_t index);

/**
 * @fn gml_t* kty04_gml_import(gml_type_t type, void *src)
 * @brief Loads the Group Members List stored in the given source, of the
 *  specified type, and returns a initialized GML structure.
 *
 * @param[in] type The type of source.
 * @param[in] src The element containing the gml.
 *
 * @return The imported GML or NULL if error.
 */
gml_t* kty04_gml_import(gml_format_t type, void *src);

/**
 * @fn int kty04_gml_export(gml_t *gml, void *dst, gml_format_t format)
 * @brief Exports the given Group Members List structure into the given destination.
 *
 * @param[in] gml The GML structure to save.
 * @param[in] dst The destination.
 * @param[in] format The type of destination.
 *
 * @return IOK or IERROR
 */
int kty04_gml_export(gml_t *gml, void *dst, gml_format_t format);

/** 
 * @fn int kty04_gml_export_new_entry(void *entry, void *dst, gml_format_t format)
 * @brief Adds the given new entry to the GML exported in the specified destination. 
 *
 * @param[in] entry The entry to add.
 * @param[in] dst The destination
 * @param[in] format The GML format.
 * 
 * @return IOK or IERROR.
 */
int kty04_gml_export_new_entry(void *entry, void *dst, gml_format_t format);

/** 
 * @fn int kty04_gml_compare_entries(void *entry1, void *entry2)
 * @brief Compares two kty04_gml_entry_t structures. Just tells if they have the same
 * contents or not.
 *
 * @param[in] entry1 The first operand.
 * @param[in] entry2 The second operand.
 * 
 * @return 0 if both entries have the same contents != 0 if not. If an error
 *  occurs, errno is updated.
 */
int kty04_gml_compare_entries(void *entry1, void *entry2);

/**
 * @var kty04_gml_handle
 * @brief Set of functions for managing KTY04 GMLs.
 */
static const gml_handle_t kty04_gml_handle = {
  GROUPSIG_KTY04_CODE, /**< Scheme code. */
  &kty04_gml_init, /**< GML initialization. */
  &kty04_gml_free, /**< GML free. */
  &kty04_gml_insert, /**< Insert a new entry. */
  &kty04_gml_remove, /**< Remove an existing entry. */
  &kty04_gml_get, /**< Gets (without removing) a specific entry. */
  &kty04_gml_import, /**< Import a GML at an external source. */
  &kty04_gml_export, /**< Export the GML to an external destination. */
  &kty04_gml_export_new_entry, /**< Add a new entry to an exported GML. */
};

#endif /* KTY04_GML_H */

/* kty04_gml.h ends here */
