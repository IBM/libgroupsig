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

#ifndef _GRP_KEY_HANDLES_H
#define _GRP_KEY_HANDLES_H

#include "grp_key.h"
/* #include "groupsig/kty04/grp_key.h" */
#include "groupsig/bbs04/grp_key.h"
/* #include "groupsig/cpy06/grp_key.h" */
#include "groupsig/gl19/grp_key.h"
#include "groupsig/ps16/grp_key.h"
#include "groupsig/klap20/grp_key.h"
#include "groupsig/dl21/grp_key.h"
#include "groupsig/dl21seq/grp_key.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def GROUPSIG_GRP_KEY_HANDLES_N
 * @brief Number of supported group key implementations.
 */
#define GROUPSIG_GRP_KEY_HANDLES_N 6

/**
 * @var GROUPSIG_GRP_KEY_HANDLES
 * @brief Set of handles for the known group key implementations.
 */
static const grp_key_handle_t *GROUPSIG_GRP_KEY_HANDLES[GROUPSIG_GRP_KEY_HANDLES_N] = { 
  /* &kty04_grp_key_handle, */
  &bbs04_grp_key_handle,
  /* &cpy06_grp_key_handle, */
  &gl19_grp_key_handle,
  &ps16_grp_key_handle,
  &klap20_grp_key_handle,
  &dl21_grp_key_handle,
  &dl21seq_grp_key_handle,
};

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif
  
#endif /* _GRP_KEY_HANDLES_H */

/* grp_key_handles.h ends here */
