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

#ifndef _IDENTITY_HANDLES_H
#define _IDENTITY_HANDLES_H

#include "identity.h"
/* #include "groupsig/kty04/identity.h" */
/* #include "groupsig/cpy06/identity.h" */
#include "groupsig/gl19/identity.h"
#include "groupsig/dl21/identity.h"
#include "groupsig/dl21seq/identity.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def IDENTITY_HANDLES_N
 * @brief Number of supported identity handles.
 */
#define IDENTITY_HANDLES_N 3

/**
 * @var IDENTITY_HANDLES
 * @brief List of supported identity handles.
 */
static const identity_handle_t *IDENTITY_HANDLES[IDENTITY_HANDLES_N] = {
  /* &kty04_identity_handle, */
  /* &cpy06_identity_handle, */
  &gl19_identity_handle,
  &dl21_identity_handle,
  &dl21seq_identity_handle,  
};

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif
  
#endif /* _IDENTITY_HANDLES_H */

/* identity_handles.h ends here */
