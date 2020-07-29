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

#ifndef _GML_H
#define _GML_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @typedef gml_format_t
 * @brief Enumeration of known GML formats.
 */
typedef enum {
  GML_FILE,
  GML_DATABASE,
} gml_format_t;

/**
 * @struct gml_t
 * @brief A basic GML structure.
 *
 * @todo Improve the structure for O(1) insert and deletes!
 */
typedef struct {
  uint8_t scheme; /**< The scheme of which this GML is an instance of. */
  void **entries; /**< An array of pointers to the entries in the GML. */
  uint64_t n; /**< The number of entries in the previous array. */
} gml_t;

/**
 * @typedef gml_t* (*gml_init_f)(void)
 * @brief Type of functions for initializing GMLs.
 */
typedef gml_t* (*gml_init_f)(void);

/**
 * @typedef int (*gml_free_f)(gml_t *gml)
 * @brief Type of functions for freeing GMLs.
 */
typedef int (*gml_free_f)(gml_t *gml);

/** 
 * @typedef int (*gml_insert_f)(gml_t *gml, void *entry)
 * @brief Type of functions for inserting new entries in GMLs.
 */
typedef int (*gml_insert_f)(gml_t *gml, void *entry);

/** 
 * @typedef int (*gml_remove_f)(gml_t *gml, uint64_t index)
 * @brief Type of functions for removing entries from GMLs.
 */
typedef int (*gml_remove_f)(gml_t *gml, uint64_t index);

/**
 * @typedef void* (*gml_get_f)(gml_t *gml, uint64_t index);
 * @brief Type of functions for getting entries from GMLs.
 */
typedef void* (*gml_get_f)(gml_t *gml, uint64_t index);

/**
 * @typedef gml_t* (*gml_import_f)(gml_format_t format, void *src)
 * @brief Type of functions for importing GMLs from external sources.
 */
typedef gml_t* (*gml_import_f)(gml_format_t format, void *src);

/**
 * @typedef int (*gml_export_f)(gml_t *gml, void *dst, gml_format_t format)
 * @brief Type of functions for exporting for exporting GMLs.
 */
typedef int (*gml_export_f)(gml_t *gml, void *dst, gml_format_t format);

/**
 * @typedef int (*gml_export_new_entry_f)(void *entry, void *dst, gml_format_t format)
 * @brief Type of functions for adding new entries to exported GMLs.
 */
typedef int (*gml_export_new_entry_f)(void *entry, void *dst, gml_format_t format);

/**
 * @struct gml_handle_t
 * @brief Set of functions for managing GMLs.
 */
typedef struct {
  uint8_t scheme; /**< The GML scheme. */
  gml_init_f gml_init; /**< Initializes GMLs. */
  gml_free_f gml_free; /**< Frees GMLs. */
  gml_insert_f gml_insert; /**< Inserts new entries in GMLs. */
  gml_remove_f gml_remove; /**< Removes entries from GMLs. */
  gml_get_f gml_get; /**< Gets entries (without removing them. From GMLs. */
  gml_import_f gml_import; /**< Imports GMLs from external sources. */
  gml_export_f gml_export; /**< Exports GMLs. */
  gml_export_new_entry_f gml_export_new_entry; /**< Directly adds new entries to exported GMLs. */
} gml_handle_t;

/**
 * @def typedef int (*gml_cmp_entries_f)(void *entry1, void *entry2)
 * Functions for comparing GML entries must follow this type.
 * Must set errno if an error occurs.
 */
typedef int (*gml_cmp_entries_f)(void *entry1, void *entry2);

/** 
 * @fn const gml_handle_t* gml_handle_from_code(uint8_t code)
 * @brief Returns the GML handles associated to the given code.
 *
 * @param[in] code A valid GML handles code. 
 * 
 * @return A pointer to the retreived GML handle or NULL if error.
 */
const gml_handle_t* gml_handle_from_code(uint8_t code);

/** 
 * @fn gml_t* gml_init(uint8_t scheme)
 * @brief Initializes a GML structure.
 *
 * @param[in] scheme The scheme code.
 * 
 * @return A pointer to the initialized structure.
 */
gml_t* gml_init(uint8_t scheme);

/** 
 * @fn int gml_free(gml_t *gml)
 * @brief Frees the received GML structure. Note that it does not free the entries.
 * If memory has been allocated for them, the caller must free it.
 *
 * @param[in,out] gml The GML to free.
 * 
 * @return IOK.
 */
int gml_free(gml_t *gml);

/** 
 * @fn int gml_insert(gml_t *gml, void *entry)
 * @brief Inserts the given entry into the gml. The memory pointed by the new entry is
 * not duplicated.
 *
 * @param[in,out] gml The GML.
 * @param[in] entry The entry to insert.
 * 
 * @return IOK or IERROR with errno updated.
 */
int gml_insert(gml_t *gml, void *entry);

/** 
 * @fn int gml_remove(gml_t *gml, uint64_t index)
 * @brief Removes the entry at position <i>index</i> from the GML. The caller is 
 * responsible for removing the contents of the entry itself.
 *
 * @param[in,out] gml The GML.
 * @param[in] index The index of the entry to remove.
 * 
 * @return IOK or IERROR with errno updated.
 */
int gml_remove(gml_t *gml, uint64_t index);

/** 
 * @fn void* gml_get(gml_t *gml, uint64_t index)
 * @brief Returns a pointer to the GML entry at the specified position.
 *
 * @param[in] gml The GML.
 * @param[in] index The index of the entry to retrieve.
 * 
 * @return A pointer to the specified entry or NULL if error.
 */
void* gml_get(gml_t *gml, uint64_t index);

/** 
 * @fn gml_t* gml_import(uint8_t code, gml_format_t format, void *source)
 * @brief Imports a GML of the specified scheme, from the given source of the specified
 * type.
 *
 * @param[in] code The type of GML. 
 * @param[in] format The type of source.
 * @param[in] source The source.
 * 
 * @return A pointer to the imported GML or NULL with errno set.
 */
gml_t* gml_import(uint8_t code, gml_format_t format, void *source);

/** 
 * @fn int gml_export(gml_t *gml, void *dst, gml_format_t format)
 * @brief Exports the given GML into the given destination.
 *
 * @param[in] gml The GML to export. 
 * @param[in] dst The destination. 
 * @param[in] format The type of destination.
 * 
 * @return IOK or IERROR with errno set.
 */
int gml_export(gml_t *gml, void *dst, gml_format_t format);

/** 
 * @fn int gml_export_new_entry(uint8_t scheme, void *entry, void *dst, 
 *                              gml_format_t format)
 * @brief Given an *existing* GML stored in the dst, updates it adding the specified
 * entry.
 *
 * @param[in] scheme The scheme of the GML.
 * @param[in] entry The entry to add.
 * @param[in] dst The destination.
 * @param[in] format The format of the destination.
 * 
 * @return IOK or IERROR.
 */
int gml_export_new_entry(uint8_t scheme, void *entry, void *dst, 
			 gml_format_t format);

/** 
 * @fn int gml_compare_entries(int *eq, void *entry1, void *entry2, 
 *                             gml_cmp_entries_f cmp)
 * @brief Compares GML entries using the specified comparison function. 
 *
 * Uses the given comparison function to return a measure of similarity between
 * the received entries. If 0, they are equal, if != 0, they are different.
 * This is not part of a GML handle, since one might want to compare entries
 * of different types (using a all-in-one conversion and comparision function).
 * Thus, this function is not linked to any specific GML type.
 *
 * @param[in,out] eq The result of the comparison.
 * @param[in] entry1 One entry to compare.
 * @param[in] entry2 The other entry to compare.
 * @param[in] cmp A pointer to the comparison function.
 * 
 * @return 0 if both entries are equal according to the given cmp function, 
 * 1 if not.
 */
int gml_compare_entries(int *eq, void *entry1, void *entry2, gml_cmp_entries_f cmp);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _GML_H */

/* gml.h ends here */
