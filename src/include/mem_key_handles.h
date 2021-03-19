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

#ifndef _MEM_KEY_HANDLES_H
#define _MEM_KEY_HANDLES_H

#include "mem_key.h"
/* #include "groupsig/kty04/mem_key.h" */
#include "groupsig/bbs04/mem_key.h"
/* #include "groupsig/cpy06/mem_key.h" */
#include "groupsig/gl19/mem_key.h"
#include "groupsig/ps16/mem_key.h"
#include "groupsig/klap20/mem_key.h"
#include "groupsig/dl21/mem_key.h"
#include "groupsig/dl21seq/mem_key.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def GROUPSIG_MEM_KEY_HANDLES_N
 * @brief Number of known handles of member key schemes.
 */
#define GROUPSIG_MEM_KEY_HANDLES_N 6

/**
 * @var GROUPSIG_MEM_KEY_HANDLES
 * @brief List of handles of supported member key schemes.
 */
static const mem_key_handle_t *GROUPSIG_MEM_KEY_HANDLES[GROUPSIG_MEM_KEY_HANDLES_N] = { 
  /* &kty04_mem_key_handle, */
  &bbs04_mem_key_handle,
  /* &cpy06_mem_key_handle, */
  &gl19_mem_key_handle,
  &ps16_mem_key_handle,
  &klap20_mem_key_handle,
  &dl21_mem_key_handle,
  &dl21seq_mem_key_handle,  
};

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _MEM_KEY_HANDLES_H */

/* mem_key_handles.h ends here */
