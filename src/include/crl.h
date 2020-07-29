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

#ifndef _CRL_H
#define _CRL_H

#include "trapdoor.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @enum crl_format_t
 * @brief Defines the set of all the CRL known formats. All the specific types
 *  of CRLs must support at least one of the following.
 */
typedef enum {
  CRL_FILE,
  CRL_DATABASE,
} crl_format_t;

/**
 * @struct crl_t 
 * @brief A CRL structure.
 *
 * @todo Improve the structure for O(1) insert and deletes!
 */
typedef struct {
  uint8_t scheme; /**< The CRL scheme. */
  void **entries; /**< An array of pointers to the entries in the CRL.
		     The specific type of entry depends on the CRL 
		     implementation. */
  uint64_t n; /**< The number of entries in the previous array. */
} crl_t;


/**
 * @typedef crl_t* (*crl_init_f)(void)
 * @brief Function type for initializing CRLs.
 */
typedef crl_t* (*crl_init_f)(void);

/**
 * @typedef int (*crl_free_f)(crl_t *crl)
 * @brief Function type for freeing CRLs.
 */
typedef int (*crl_free_f)(crl_t *crl);

/**
 * @typedef int (*crl_insert_f)(crl_t *crl, void *entry)
 * @brief Function type for inserting a new entry into a CRL.
 */
typedef int (*crl_insert_f)(crl_t *crl, void *entry);

/**
 * @typedef int (*crl_remove_f)(crl_t *crl, uint64_t index)
 * @brief Function type for removing the entry at the given position within a
 *  CRL.
 */
typedef int (*crl_remove_f)(crl_t *crl, uint64_t index);

/**
 * @typedef int (*crl_get_f)(crl_t *crl, uint64_t index)
 * @brief Function type for getting (without removing) the entry at the given 
 *  position within a CRL.
 */
typedef void* (*crl_get_f)(crl_t *crl, uint64_t index);

/**
 * @typedef crl_t* (*crl_import_f)(crl_format_t format, void *src)
 * @brief Function type for importing a CRL of the given format from the
 *  specified source.
 */
typedef crl_t* (*crl_import_f)(crl_format_t format, void *src);

/**
 * @typedef crl_t* (*crl_export_f)(crl_t *crl, void *dst, crl_format_t format)
 * @brief Function type for exporting a CRL to the given destination, using the
 *  specified format.
 */
typedef int (*crl_export_f)(crl_t *crl, void *dst, crl_format_t format);

/**
 * @typedef int (*crl_entry_exists_f)(crl_t *crl, void *entry)
 * @brief Function for testing whether the specified entry already exists in a
 *  CRL.
 */
typedef int (*crl_entry_exists_f)(crl_t *crl, void *entry);

/**
 * @typedef int (*crl_trapdoor_exists_f)(crl_t *crl, trapdoor_t *trap)
 * @brief Function for testing whether an entry with the specified trapdoor 
 *  already exists in a CRL.
 */
typedef int (*crl_trapdoor_exists_f)(crl_t *crl, trapdoor_t *trap);

/**
 * @struct crl_handle_t
 * @brief Bundles together a set of function handles for managing CRL structures.
 */
typedef struct {
  uint8_t scheme; /**< The scheme code. */
  crl_init_f crl_init; /**< The CRL initialization function. */
  crl_free_f crl_free; /**< The CRL freeing function. */
  crl_insert_f crl_insert; /**< The CRL entry insertion function. */
  crl_remove_f crl_remove; /**< The CRL entry removing function. */
  crl_get_f crl_get; /**< Gets CRL entries. */
  crl_import_f crl_import; /**< For CRL import. */
  crl_export_f crl_export; /**< For CRL export. */
  crl_entry_exists_f crl_entry_exists; /**< For entry testing. */
  crl_trapdoor_exists_f crl_trapdoor_exists; /**< For trapdoor-entry testing. */
} crl_handle_t;

/**
 * @def typedef int (*crl_cmp_entries_f)(void *entry1, void *entry2)
 * Functions for comparing CRL entries must follow this type.
 * Must set errno if an error occurs.
 */
typedef int (*crl_cmp_entries_f)(void *entry1, void *entry2);

/** 
 * @fn const crl_handle_t* crl_handle_from_code(uint8_t code)
 * Returns the CRL handles associated to the given code.
 *
 * @param[in] code A valid CRL handles code. 
 * 
 * @return A pointer to the retreived CRL handle or NULL if error.
 */
const crl_handle_t* crl_handle_from_code(uint8_t code);

/** 
 * @fn crl_t* crl_init(uint8_t scheme)
 * Initializes a CRL structure.
 *
 * @param[in] scheme The scheme code.
 * 
 * @return A pointer to the initialized structure.
 */
crl_t* crl_init(uint8_t scheme);

/** 
 * @fn int crl_free(crl_t *crl)
 * Frees the received CRL structure. Note that it does not free the entries.
 * If memory has been allocated for them, the caller must free it.
 *
 * @param[in,out] crl The CRL to free.
 * 
 * @return IOK.
 */
int crl_free(crl_t *crl);

/** 
 * @fn int crl_insert(crl_t *crl, void *entry)
 * Inserts the given entry into the crl. The memory pointed by the new entry is
 * not duplicated.
 *
 * @param[in,out] crl The CRL.
 * @param[in] entry The entry to insert.
 * 
 * @return IOK or IERROR with errno updated.
 */
int crl_insert(crl_t *crl, void *entry);

/** 
 * @fn int crl_remove(crl_t *crl, uint64_t index)
 * Removes the entry at position <i>index</i> from the CRL. The caller is 
 * responsible for removing the contents of the entry itself.
 *
 * @param[in,out] crl The CRL.
 * @param[in] index The index of the entry to remove.
 * 
 * @return IOK or IERROR with errno updated.
 */
int crl_remove(crl_t *crl, uint64_t index);

/** 
 * @fn void* crl_get(crl_t *crl, uint64_t index)
 * Returns a pointer to the CRL entry at the specified position.
 *
 * @param[in] crl The CRL.
 * @param[in] index The index of the entry to retrieve.
 * 
 * @return A pointer to the specified entry or NULL if error.
 */
void* crl_get(crl_t *crl, uint64_t index);

/** 
 * @fn crl_t* crl_import(uint8_t code, crl_format_t format, void *source)
 * Imports a CRL of the specified scheme, from the given source of the specified
 * type.
 *
 * @param[in] code The type of CRL. 
 * @param[in] format The type of source.
 * @param[in] source The source.
 * 
 * @return A pointer to the imported CRL or NULL with errno set.
 */
crl_t* crl_import(uint8_t code, crl_format_t format, void *source);

/** 
 * @fn int crl_export(crl_t *crl, void *dst, crl_format_t format)
 * Exports the given CRL into the given destination.
 *
 * @param[in] crl The CRL to export. 
 * @param[in] dst The destination. 
 * @param[in] format The type of destination.
 * 
 * @return IOK or IERROR with errno set.
 */
int crl_export(crl_t *crl, void *dst, crl_format_t format);

/** 
 * @fn void* crl_entry_init(crl_t *crl)
 * Initializes and returns an entry of the type stored by the given CRL.
 * 
 * @param[in] crl The CRL.
 * 
 * @return A pointer to the initialized entry, or NULL if error.
 */
void* crl_entry_init(crl_t *crl);

/** 
 * @fn int crl_compare_entries(int *eq, void *entry1, void *entry2, 
                               crl_cmp_entries_f cmp)
 * Uses the given comparison function to return a measure of similarity between
 * the received entries. If 0, they are equal, if != 0, they are different.
 * This is not part of a CRL handle, since one might want to compare entries
 * of different types (using a all-in-one conversion and comparision function).
 * Thus, this function is not linked to any specific CRL type.
 *
 * @param[in,out] eq The result of the comparison.
 * @param[in] entry1 One entry to compare.
 * @param[in] entry2 The other entry to compare.
 * @param[in] cmp A pointer to the comparison function.
 * 
 * @return 0 if both entries are equal according to the given cmp function, 
 * 1 if not.
 */
int crl_compare_entries(int *eq, void *entry1, void *entry2, crl_cmp_entries_f cmp);

/** 
 * @fn int crl_entry_exists(crl_t *crl, void *entry);
 * Returns 1 if the entry exists in the given CRL, 0 if not. 
 *
 * @param[in] crl The CRL
 * @param[in] entry The CRL entry.
 * 
 * @return 1 if the entry exits, 0 if not. Errno is set on error.
 */
int crl_entry_exists(crl_t *crl, void *entry);

/** 
 * @fn int crl_entry_exists(crl_t *crl, trapdoor_t *trap);
 * Returns 1 if the entry exists in the given CRL with the given trapdoor, 0 if not. 
 *
 * @param[in] crl The CRL.
 * @param[in] trap The trapdoor.
 * 
 * @return 1 if the entry exits, 0 if not. Errno is set on error.
 */
int crl_trapdoor_exists(crl_t *crl, trapdoor_t *trap);

/* /\** */
/*  * @def typedef int (*crl_cmp_entries_f)(void *entry1, void *entry2) */
/*  * Functions for comparing CRL entries must follow this type. */
/*  * Must set errno if an error occurs. */
/*  *\/ */
/* typedef int (*crl_cmp_entries_f)(void *entry1, void *entry2); */

/* /\**  */
/*  * @fn crl_t* crl_init() */
/*  * Initializes a CRL structure. */
/*  *  */
/*  * @return A pointer to the initialized structure. */
/*  *\/ */
/* crl_t* crl_init(); */

/* /\**  */
/*  * @fn int crl_free(crl_t *crl) */
/*  * Frees the received CRL structure. Note that it does not free the entries. */
/*  * If memory has been allocated for them, the caller must free it. */
/*  * */
/*  * @param[in,out] crl The CRL to free. */
/*  *  */
/*  * @return IOK. */
/*  *\/ */
/* int crl_free(crl_t *crl); */

/* /\**  */
/*  * @fn int crl_insert(crl_t *crl, void *entry) */
/*  * Inserts the given entry into the crl. The memory pointed by the new entry is */
/*  * not duplicated. */
/*  * */
/*  * @param[in,out] crl The CRL. */
/*  * @param[in] entry The entry to insert. */
/*  *  */
/*  * @return IOK or IERROR with errno updated. */
/*  *\/ */
/* int crl_insert(crl_t *crl, void *entry); */

/* /\**  */
/*  * @fn int crl_remove(crl_t *crl, uint64_t index) */
/*  * Removes the entry at position <i>index</i> from the CRL. The caller is  */
/*  * responsible for removing the contents of the entry itself. */
/*  * */
/*  * @param[in,out] crl The CRL. */
/*  * @param[in] index The index of the entry to remove. */
/*  *  */
/*  * @return IOK or IERROR with errno updated. */
/*  *\/ */
/* int crl_remove(crl_t *crl, uint64_t index); */

/* /\**  */
/*  * @fn void* crl_get(crl_t *crl, uint64_t index) */
/*  * Returns a pointer to the CRL entry at the specified position. */
/*  * */
/*  * @param[in] crl The CRL. */
/*  * @param[in] index The index of the entry to retrieve. */
/*  *  */
/*  * @return A pointer to the specified entry or NULL if error. */
/*  *\/ */
/* void* crl_get(crl_t *crl, uint64_t index); */

/* /\**  */
/*  * @fn int crl_compare_entries(int *eq, void *entry1, void *entry2,  */
/*                                crl_cmp_entries_f cmp) */
/*  * Uses the given comparison function to return a measure of similarity between */
/*  * the received entries. If 0, they are equal, if != 0, they are different. */
/*  * */
/*  * @param[in,out] eq The result of the comparison. */
/*  * @param[in] entry1 One entry to compare. */
/*  * @param[in] entry2 The other entry to compare. */
/*  * @param[in] cmp A pointer to the comparison function. */
/*  *  */
/*  * @return  */
/*  *\/ */
/* int crl_compare_entries(int *eq, void *entry1, void *entry2, crl_cmp_entries_f cmp); */

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _CRL_H */

/* crl.h ends here */
