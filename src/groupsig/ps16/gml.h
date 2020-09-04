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

#ifndef _PS16_GML_H
#define _PS16_GML_H

#include "types.h"
#include "sysenv.h"
#include "include/gml.h"
#include "groupsig/ps16/identity.h"
#include "shim/pbc_ext.h"
#include "ps16.h"

/**
 * @def PS16_SUPPORTED_GML_FORMATS_N
 * @brief Number GML formats supported by PS16.
 */
#define PS16_SUPPORTED_GML_FORMATS_N 1

/**
 * @var PS16_SUPPORTED_GML_FORMATS
 * @brief List of GML formats supported by PS16. 
 */
static const int PS16_SUPPORTED_GML_FORMATS[PS16_SUPPORTED_GML_FORMATS_N] = {
  GML_FILE,
};

/** 
 * @struct ps16_gml_entry_t
 * @brief Structure for PS16 GML entries.
 */
typedef struct {
  identity_t *id; /**< Member's ID. */
  pbcext_element_G1_t *tau;
  pbcext_element_G2_t *ttau;
} ps16_gml_entry_t;

/* Entry public functions */

/**
 * @fn ps16_gml_entry_t* ps16_gml_entry_init()
 * @brief Creates a new GML entry and initializes its fields.
 *
 * @return The created gml entry or NULL if error.
 */
ps16_gml_entry_t* ps16_gml_entry_init();

/**
 * @fn int ps16_gml_entry_free(ps16_gml_entry_t *entry)
 * @brief Frees the fields of the given GML entry.
 *
 * @param[in,out] entry The GML entry to free.
 *
 * @return IOK or IERROR
 */
int ps16_gml_entry_free(ps16_gml_entry_t *entry);

/** 
 * @fn char* ps16_gml_entry_to_string(ps16_gml_entry_t *entry)
 * @brief Converts the received PS16 GML entry to a printable string.
 *
 * @param[in] entry The GML entry.
 * 
 * @return The converted string or NULL if error.
 */
char* ps16_gml_entry_to_string(ps16_gml_entry_t *entry);

/* List public functions */

/** 
 * @fn gml_t* ps16_gml_init()
 * @brief Initializes a GML structure.
 * 
 * @return A pointer to the initialized structure.
 */
gml_t* ps16_gml_init();

/** 
 * @fn int ps16_gml_free(gml_t *gml)
 * @brief Frees the received GML structure. 
 *
 * Note that it does not free the entries. If memory has been allocated for 
 * them, the caller must free it.
 *
 * @param[in,out] gml The GML to free.
 * 
 * @return IOK.
 */
int ps16_gml_free(gml_t *gml);

/** 
 * @fn int ps16_gml_insert(gml_t *gml, void *entry)
 * @brief Inserts the given entry into the gml. The memory pointed by the new entry is
 * not duplicated.
 *
 * @param[in,out] gml The GML.
 * @param[in] entry The entry to insert.
 * 
 * @return IOK or IERROR with errno updated.
 */
int ps16_gml_insert(gml_t *gml, void *entry);

/** 
 * @fn int ps16_gml_remove(gml_t *gml, uint64_t index)
 * @brief Removes the entry at position <i>index</i> from the GML. The caller is 
 * responsible for removing the contents of the entry itself.
 *
 * @param[in,out] gml The GML.
 * @param[in] index The index of the entry to remove.
 * 
 * @return IOK or IERROR with errno updated.
 */
int ps16_gml_remove(gml_t *gml, uint64_t index);

/** 
 * @fn void* ps16_gml_get(gml_t *gml, uint64_t index)
 * @brief Returns a pointer to the GML entry at the specified position.
 *
 * @param[in] gml The GML.
 * @param[in] index The index of the entry to retrieve.
 * 
 * @return A pointer to the specified entry or NULL if error.
 */
void* ps16_gml_get(gml_t *gml, uint64_t index);

/**
 * @fn gml_t* ps16_gml_import(gml_type_t type, void *src)
 * @brief Loads the Group Members List stored in the given source, of the
 *  specified type, and returns a initialized GML structure.
 *
 * @param[in] type The type of source.
 * @param[in] src The element containing the gml.
 *
 * @return The imported GML or NULL if error.
 */
gml_t* ps16_gml_import(gml_format_t type, void *src);

/**
 * @fn int ps16_gml_export(gml_t *gml, void *dst, gml_format_t format)
 * @brief Exports the given Group Members List structure into the given destination.
 *
 * @param[in] gml The GML structure to save.
 * @param[in] dst The destination.
 * @param[in] format The type of destination.
 *
 * @return IOK or IERROR
 */
int ps16_gml_export(gml_t *gml, void *dst, gml_format_t format);

/** 
 * @fn int ps16_gml_export_new_entry(void *entry, void *dst, gml_format_t format)
 * @brief Adds the given new entry to the GML exported in the specified destination. 
 *
 * @param[in] entry The entry to add.
 * @param[in] dst The destination
 * @param[in] format The GML format.
 * 
 * @return IOK or IERROR.
 */
int ps16_gml_export_new_entry(void *entry, void *dst, gml_format_t format);

/** 
 * @fn int ps16_gml_compare_entries(void *entry1, void *entry2)
 * @brief Compares two ps16_gml_entry_t structures. Just tells if they have the same
 * contents or not.
 *
 * @param[in] entry1 The first operand.
 * @param[in] entry2 The second operand.
 * 
 * @return 0 if both entries have the same contents != 0 if not. If an error
 *  occurs, errno is updated.
 */
int ps16_gml_compare_entries(void *entry1, void *entry2);

/**
 * @var ps16_gml_handle
 * @brief Set of functions for managing PS16 GMLs.
 */
static const gml_handle_t ps16_gml_handle = {
  GROUPSIG_PS16_CODE, /**< Scheme code. */
  &ps16_gml_init, /**< GML initialization. */
  &ps16_gml_free, /**< GML free. */
  &ps16_gml_insert, /**< Insert a new entry. */
  &ps16_gml_remove, /**< Remove an existing entry. */
  &ps16_gml_get, /**< Gets (without removing) a specific entry. */
  &ps16_gml_import, /**< Import a GML at an external source. */
  &ps16_gml_export, /**< Export the GML to an external destination. */
  &ps16_gml_export_new_entry, /**< Add a new entry to an exported GML. */
};

#endif /* PS16_GML_H */

/* ps16_gml.h ends here */
