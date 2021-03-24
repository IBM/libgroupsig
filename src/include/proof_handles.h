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

#ifndef _PROOF_HANDLES_H
#define _PROOF_HANDLES_H

#include <stdlib.h>
#include "proof.h"
/* #include "groupsig/kty04/proof.h" */
/* #include "groupsig/cpy06/proof.h" */
#include "groupsig/ps16/proof.h"
#include "groupsig/klap20/proof.h"
#include "groupsig/dl21/proof.h"
#include "groupsig/dl21seq/proof.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def GROUPSIG_PROOF_HANDLES_N
 * @brief Number of supported proof bundles.
 */
#define GROUPSIG_PROOF_HANDLES_N 4

/**
 * @var GROUPSIG_PROOF_HANDLES
 * @brief List of supported bundles for managing proofs.
 */
static const groupsig_proof_handle_t *GROUPSIG_PROOF_HANDLES[GROUPSIG_PROOF_HANDLES_N] = {
    //&kty04_proof_handle,
    //&cpy06_proof_handle,
  &ps16_proof_handle,
  &klap20_proof_handle,
  &dl21_proof_handle,
  &dl21seq_proof_handle,
};

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _PROOF_HANDLES_H */

/* proof_handles.h ends here */
