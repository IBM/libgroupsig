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
 * @struct gml_entry_t
 * @brief A generic structure for representing entries in GMLs.
 * 
 * It contains one concrete field, id, which will be the unique integer
 * identifying each member in group signatures. The pointer to void can
 * be used by the schemes to point to custom structures containing the
 * trapdoor information they need.
 */
typedef struct {
  uint8_t scheme; /**< The scheme of which this GML entry is an instance of. */
  uint64_t id; /**< The identity of the user represented by the entry. */
  void *data; /**< Opaque pointer for schemes. */
} gml_entry_t;

/**
 * @struct gml_t
 * @brief A basic GML structure.
 */
typedef struct {
  uint8_t scheme; /**< The scheme of which this GML is an instance of. */
  gml_entry_t **entries; /**< An array of pointers to the entries in the GML. */
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
 * @typedef int (*gml_insert_f)(gml_t *gml, gml_entry_t *entry)
 * @brief Type of functions for inserting new entries in GMLs.
 */
typedef int (*gml_insert_f)(gml_t *gml, gml_entry_t *entry);

/** 
 * @typedef int (*gml_remove_f)(gml_t *gml, uint64_t index)
 * @brief Type of functions for removing entries from GMLs.
 */
typedef int (*gml_remove_f)(gml_t *gml, uint64_t index);

/**
 * @typedef gml_entry_t* (*gml_get_f)(gml_t *gml, uint64_t index);
 * @brief Type of functions for getting entries from GMLs.
 */
typedef gml_entry_t* (*gml_get_f)(gml_t *gml, uint64_t index);

/**
 * @typedef int (*gml_export_f)(byte_t **bytes, uint32_t *size, gml_t *gml)
 * @brief Type of functions for exporting GMLs.
 */
typedef int (*gml_export_f)(byte_t **bytes,
			    uint32_t *size,
			    gml_t *gml);
  
/**
 * @typedef gml_t* (*gml_import_f)(byte_t *bytes, uint32_t size)
 * @brief Type of functions for importing GMLs.
 */
typedef gml_t* (*gml_import_f)(byte_t *bytes, uint32_t size);

/**
 * @typedef gml_entry_t* (*gml_entry_init_f)()
 * @brief Type of functions for initializing individual entries of GMLs.
 */  
typedef gml_entry_t* (*gml_entry_init_f)();

/**
 * @typedef int (*gml_entry_free_f)(gml_entry_t *entry)
 * @brief Type of functions for freeing individual entries of GMLs.
 */  
typedef int (*gml_entry_free_f)(gml_entry_t *entry);  

/**
 * @typedef int (*gml_entry_get_size_f)(gml_get_sizet *entry)
 * @brief Type of functions for returning the size in bytes that a given entry
 *  would need to be represented as a byte array.
 */  
typedef int (*gml_entry_get_size_f)(gml_entry_t *entry);
  
/**
 * @typedef int (*gml_entry_export_f)(byte_t **bytes, 
 *                                    uint32_t *size, 
 *                                    gml_entry_t *entry)
 * @brief Type of functions for exporting individual entries of GMLs.
 */  
typedef int (*gml_entry_export_f)(byte_t **bytes,
				  uint32_t *size,
				  gml_entry_t *entry);

/**
 * @typedef gml_t* (*gml_entry_import_f)(byte_t *bytes, uint32_t size)
 * @brief Type of functions for importing individual GML entries.
 */  
typedef gml_entry_t* (*gml_entry_import_f)(byte_t *bytes, uint32_t size);

/**
 * @typedef char* (*gml_entry_to_string_f)(gml_entry_t *entry)
 * @brief Type of functions for producing human readable strings of GML
 *  entries.
 */  
typedef char* (*gml_entry_to_string_f)(gml_entry_t *entry);  

/**
 * @struct gml_handle_t
 * @brief Set of functions for managing GMLs.
 */
typedef struct {
  uint8_t scheme; /**< The GML scheme. */
  gml_init_f init; /**< Initializes GMLs. */
  gml_free_f free; /**< Frees GMLs. */
  gml_insert_f insert; /**< Inserts new entries in GMLs. */
  gml_remove_f remove; /**< Removes entries from GMLs. */
  gml_get_f get; /**< Gets entries without removing them from GMLs. */
  gml_import_f gimport; /**< Imports GMLs from external sources. */
  gml_export_f gexport; /**< Exports GMLs. */
  gml_entry_init_f entry_init; /**< Initializes an entry. */ 
  gml_entry_free_f entry_free; /**< Frees an entry. */
  gml_entry_get_size_f entry_get_size; /**< Gets the size in bytes of an entry. */  
  gml_entry_export_f entry_export; /**< Exports an entry. */
  gml_entry_import_f entry_import; /**< Imports an entry. */
  gml_entry_to_string_f entry_to_string; /**< Returns a human readable string. */
} gml_handle_t;

/**
 * @def typedef int (*gml_cmp_entries_f)(gml_entry_t *entry1, 
 *                                       gml_entry_t *entry2)
 * Functions for comparing GML entries must follow this type.
 * Must set errno if an error occurs.
 */
typedef int (*gml_cmp_entries_f)(gml_entry_t *entry1, gml_entry_t *entry2);

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
 * @fn int gml_insert(gml_t *gml, gml_entry_t *entry)
 * @brief Inserts the given entry into the gml. The memory pointed by the new 
 *  entry is not duplicated.
 *
 * @param[in,out] gml The GML.
 * @param[in] entry The entry to insert.
 * 
 * @return IOK or IERROR with errno updated.
 */
int gml_insert(gml_t *gml, gml_entry_t *entry);

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
 * @fn gml_entry_t* gml_get(gml_t *gml, uint64_t index)
 * @brief Returns a pointer to the GML entry at the specified position.
 *
 * @param[in] gml The GML.
 * @param[in] index The index of the entry to retrieve.
 * 
 * @return A pointer to the specified entry or NULL if error.
 */
gml_entry_t* gml_get(gml_t *gml, uint64_t index);

/** 
 * @fn int gml_export(byte_t **bytes, uint32_t *size, gml_t *gml)
 * @brief Exports the given GML as an array of bytes.
 *
 * @param[in,out] bytes Will be updated with the exported GML. If *gml is NULL,
 *  memory will be internally allocated. Otherwise, it must be big enough to
 *  hold all the data.
 * @param[in,out] size Will be updated with the number of bytes written into 
 *  *bytes.
 * @param[in] gml The GML structure to export.
 * 
 * @return IOK or IERROR with errno set.
 */
int gml_export(byte_t **bytes, uint32_t *size, gml_t *gml);

/** 
 * @fn gml_t* gml_import(uint8_t code, byte_t *bytes, uint32_t size)
 * @brief Imports a GML of the specified scheme, from the given array of bytes.
 *
 * @param[in] code The type of GML. 
 * @param[in] bytes The bytes to read the GML from.
 * @param[in] size The number of bytes to be read.
 * 
 * @return A pointer to the imported GML or NULL with errno set.
 */
gml_t* gml_import(uint8_t code, byte_t *bytes, uint32_t size);

/**
 * @fn gml_entry_t* gml_entry_init(uint8_t code)
 * @brief Initializes a GML entry of the given type.
 *
 * @param[in] code The type of GML.
 * 
 * @return A pointer to the new entry or NULL with errno set.
 */  
gml_entry_t* gml_entry_init(uint8_t code);

/**
 * @fn int gml_entry_free(gml_entry_t *entry)
 * @brief Frees the memory allocated for the given GML entry.
 *
 * @param[in] entry The entry to free.
 * 
 * @return A pointer to the imported GML or NULL with errno set.
 */  
int gml_entry_free(gml_entry_t *entry);

/**
 * @fn int gml_entry_get_size(gml_entry_t *entry)
 * @brief Returns the number of bytes needed to represent the given entry
 *  as a byte array.
 *
 * @param[in] entry The entry.
 * 
 * @return The number of bytes needed to export the entry, or -1 if error.
 */  
int gml_entry_get_size(gml_entry_t *entry);

/**
 * @fn int gml_entry_export(byte_t **bytes, uint32_t *size, gml_entry_t *entry)
 * @brief Exports a GML entry into an array of bytes.
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
int gml_entry_export(byte_t **bytes, uint32_t *size, gml_entry_t *entry);
  
/** 
 * @fn gml_t* gml_entry_import(uint8_t code, byte_t *bytes, uint32_t size)
 * @brief Imports a GML of the specified scheme, from the given array of bytes.
 *
 * @param[in] code The type of GML. 
 * @param[in] bytes The bytes to read the GML from.
 * @param[in] size The number of bytes to be read.
 * 
 * @return A pointer to the imported GML or NULL with errno set.
 */
gml_entry_t* gml_entry_import(uint8_t code, byte_t *bytes, uint32_t size);

/** 
 * @fn char* gml_entry_to_string(gml_entry_t *entry);
 * @brief Returns a human readable string representing the given entry.
 *
 * @param[in] entry The GML entry.
 * 
 * @return The human readable string, or NULL if error.
 */
char* gml_entry_to_string(gml_entry_t *entry);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _GML_H */

/* gml.h ends here */
