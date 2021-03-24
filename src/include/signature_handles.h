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

#ifndef _SIGNATURE_HANDLES_H
#define _SIGNATURE_HANDLES_H

#include "signature.h"
/* #include "groupsig/kty04/signature.h" */
#include "groupsig/bbs04/signature.h"
/* #include "groupsig/cpy06/signature.h" */
#include "groupsig/gl19/signature.h"
#include "groupsig/ps16/signature.h"
#include "groupsig/klap20/signature.h"
#include "groupsig/dl21/signature.h"
#include "groupsig/dl21seq/signature.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def GROUPSIG_SIGNATURE_HANDLES_N
 * @brief Number of supported set of handles for managing group signatures.
 */
#define GROUPSIG_SIGNATURE_HANDLES_N 6

/**
 * @var GROUPSIG_SIGNATURE_HANDLES
 * @brief List of supported set of handles for managing group signatures.
 */
static const groupsig_signature_handle_t *GROUPSIG_SIGNATURE_HANDLES[GROUPSIG_SIGNATURE_HANDLES_N] = { 
  /* &kty04_signature_handle, */
  &bbs04_signature_handle,
  /* &cpy06_signature_handle, */
  &gl19_signature_handle,
  &ps16_signature_handle,
  &klap20_signature_handle,
  &dl21_signature_handle,
  &dl21seq_signature_handle,  
};

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif
  
#endif /* _SIGNATURE_HANDLES_H */

/* signature_handles.h ends here */
