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

#ifndef _KLAP20_GML_H
#define _KLAP20_GML_H

#include "types.h"
#include "sysenv.h"
#include "include/gml.h"
#include "shim/pbc_ext.h"
#include "klap20.h"

/** 
 * @struct klap20_gml_entry_data_t
 * @brief Data stored in KLAP20 GML entries.
 */
typedef struct {
  pbcext_element_G2_t *SS0;
  pbcext_element_G2_t *SS1;
  pbcext_element_G2_t *ff0;
  pbcext_element_G2_t *ff1;
  pbcext_element_GT_t *tau;
} klap20_gml_entry_data_t;

/**
 * @fn gml_entry_t* klap20_gml_entry_init()
 * @brief Creates a new GML entry and initializes its fields.
 *
 * @return The created gml entry or NULL if error.
 */
gml_entry_t* klap20_gml_entry_init();

/**
 * @fn int klap20_gml_entry_free(gml_entry_t *entry)
 * @brief Frees the fields of the given GML entry.
 *
 * @param[in,out] entry The GML entry to free.
 *
 * @return IOK or IERROR
 */
int klap20_gml_entry_free(gml_entry_t *entry);

/**
 * @fn int klap20_gml_entry_get_size(gml_entry_t *entry)
 * @brief Returns the number of bytes needed to represent the given
 *  entry as an array of bytes.
 *
 * @param[in,out] entry The GML entry.
 *
 * @return The number of bytes needed to represent entry, or -1 if error.
 */
int klap20_gml_entry_get_size(gml_entry_t *entry);

/**
 * @fn int klap20_gml_entry_export(byte_t **bytes,
 *                                uint32_t *size,
 *                                gml_entry_t *entry)
 * @brief Exports a GML entry into an array of bytes.
 *
 * The used format is:
 * 
 * | code (uint8_t) | identity (uint64_t) | size_SS0 | SS0 | size_SS1 | SS1 |
 *   size_ff0 | ff0 | size_ff1 | ff1 |
 *
 * @param[in,out] bytes Will be updated with the exported entry. If *entry is 
 *  NULL,  memory will be internally allocated. Otherwise, it must be big enough
 *  to hold all the data.
 * @param[in,out] size Will be updated with the number of bytes written into 
 *  *bytes.
 * @param[in] gml The GML structure to export.
 * 
 * @return IOK or IERROR with errno set.
 */
int klap20_gml_entry_export(byte_t **bytes,
			   uint32_t *size,
			   gml_entry_t *entry);

/**
 * @fn gml_t* klap20_gml_entry_import(byte_t *bytes, uint32_t size)
 * @brief Imports a GML of the specified scheme, from the given array of bytes.
 *
 * @param[in] bytes The bytes to read the GML from.
 * @param[in] size The number of bytes to be read.
 * 
 * @return A pointer to the imported GML or NULL with errno set.
 */
gml_entry_t* klap20_gml_entry_import(byte_t *bytes, uint32_t size);

/** 
 * @fn char* klap20_gml_entry_to_string(klap20_gml_entry_t *entry)
 * @brief Converts the received KLAP20 GML entry to a printable string.
 *
 * @param[in] entry The GML entry.
 * 
 * @return The converted string or NULL if error.
 */
char* klap20_gml_entry_to_string(gml_entry_t *entry);

/** 
 * @fn gml_t* klap20_gml_init()
 * @brief Initializes a GML structure.
 * 
 * @return A pointer to the initialized structure.
 */
gml_t* klap20_gml_init();

/** 
 * @fn int klap20_gml_free(gml_t *gml)
 * @brief Frees the received GML structure. 
 *
 * Note that it does not free the entries. If memory has been allocated for 
 * them, the caller must free it.
 *
 * @param[in,out] gml The GML to free.
 * 
 * @return IOK.
 */
int klap20_gml_free(gml_t *gml);

/** 
 * @fn int klap20_gml_insert(gml_t *gml, gml_entry_t *entry)
 * @brief Inserts the given entry into the gml. The memory pointed by the new entry is
 * not duplicated.
 *
 * @param[in,out] gml The GML.
 * @param[in] entry The entry to insert.
 * 
 * @return IOK or IERROR with errno updated.
 */
int klap20_gml_insert(gml_t *gml, gml_entry_t *entry);

/** 
 * @fn int klap20_gml_remove(gml_t *gml, uint64_t index)
 * @brief Removes the entry at position <i>index</i> from the GML. The caller is 
 * responsible for removing the contents of the entry itself.
 *
 * @param[in,out] gml The GML.
 * @param[in] index The index of the entry to remove.
 * 
 * @return IOK or IERROR with errno updated.
 */
int klap20_gml_remove(gml_t *gml, uint64_t index);

/** 
 * @fn gml_entry_t* klap20_gml_get(gml_t *gml, uint64_t index)
 * @brief Returns a pointer to the GML entry at the specified position.
 *
 * @param[in] gml The GML.
 * @param[in] index The index of the entry to retrieve.
 * 
 * @return A pointer to the specified entry or NULL if error.
 */
gml_entry_t* klap20_gml_get(gml_t *gml, uint64_t index);

/**
 * @fn int klap20_gml_export(byte_t **bytes, uint32_t *size, gml_t *gml)
 * @brief Exports the given Group Members List structure into the given
 *  destination.
 *
 * The format of the exported GML is:
 *
 * | number of entries (uint64_t) | entry 1 | ... | entry n|
 *
 * @param[in,out] bytes Will be set to the byte representation of the GML. If
 *  *bytes is NULL, memory will be internally allocated. Otherwise, the array 
 *   must be big enough to store all the data.
 * @param[in,out] size Will be set to the number of bytes required to export the 
 *  GML.
 * @param[in] gml The GML structure to save.
 *
 * @return IOK or IERROR
 */
int klap20_gml_export(byte_t **bytes, uint32_t *size, gml_t *gml);

/**
 * @fn gml_t* klap20_gml_import(byte_t *bytes, uint32_t size);
 * @brief Loads the Group Members List stored in the given byte array.
 *
 * @param[in] bytes The byte array containing the GML to import.
 * @param[in] The number of bytes in the byte array.
 *
 * @return The imported GML or NULL if error.
 */
gml_t* klap20_gml_import(byte_t *bytes, uint32_t size);

/**
 * @var klap20_gml_handle
 * @brief Set of functions for managing KLAP20 GMLs.
 */
static const gml_handle_t klap20_gml_handle = {
  .scheme = GROUPSIG_KLAP20_CODE, /**< Scheme code. */
  .init = &klap20_gml_init, /**< GML initialization. */
  .free = &klap20_gml_free, /**< GML free. */
  .insert = &klap20_gml_insert, /**< Insert a new entry. */
  .remove = &klap20_gml_remove, /**< Remove an existing entry. */
  .get = &klap20_gml_get, /**< Gets (without removing) a specific entry. */
  .gimport = &klap20_gml_import, /**< Import a GML at an external source. */
  .gexport = &klap20_gml_export, /**< Export the GML to an external destination. */
  .entry_init = &klap20_gml_entry_init, /**< Initializes a GML entry. */
  .entry_free = &klap20_gml_entry_free, /**< Frees a GML entry. */
  .entry_get_size = &klap20_gml_entry_get_size,  /**< Returns the size in bytes 
                                                   of a GML entry. */
  .entry_export = &klap20_gml_entry_export, /**< Exports a GML entry. */
  .entry_import = &klap20_gml_entry_import, /**< Imports a GML entry. */
  .entry_to_string = &klap20_gml_entry_to_string, /**< Returns a human readable
						    string of a GML entry. */
  
};

#endif /* KLAP20_GML_H */

/* gml.h ends here */
