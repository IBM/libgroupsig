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

#include "mem.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "types.h"

void* mem_malloc(size_t size) {

  void *p;

  if(!size) {
    errno = EINVAL;
    return NULL;
  }

  if(!(p = malloc(size))) {
    return NULL;
  }

  memset(p, 0, size);

  return p;  

}

void* mem_realloc(void *ptr, size_t size) {

  if(!ptr) return mem_malloc(size);

  if(!(ptr = realloc(ptr, size))) {
    return NULL;
  }

  return ptr;

}

int mem_free(void *p) {

  if(!p) {
    errno = EINVAL;
    return IOK;
  }

  free(p); 
  p = NULL;
  return IOK;

}

/* mem.c ends here */
