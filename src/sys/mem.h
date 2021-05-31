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

#ifndef _MEM_H
#define _MEM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

/** 
 * @fn void* mem_malloc(size_t *size)
 * @brief Like malloc, but sets all the allocated bytes to 0.
 * 
 * @param[in] size The number of bytes to allocate.
 * 
 * @return The allocated pointer, or NULL.
 */
void* mem_malloc(size_t size);

/** 
 * @fn void* mem_realloc(void* ptr, size_t size)
 * Like normal realloc, but sets to 0 all the newly allocated memory.
 * Actually... @todo
 *
 * @param[in,out] ptr A pointer to the memory to reallocate.
 * @param[in] size The new size.
 * 
 * @return A pointer to the reallocated memory.
 */
void* mem_realloc(void* ptr, size_t size);

/** 
 * @fn int mem_free(void* p)
 * @brief Frees the given pointer and sets it to NULL;
 * 
 * @param[in,out] p The pointer to free.
 * 
 * @return IOK.
 */
int mem_free(void *p);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _MEM_H */

/* mem.h ends here */
