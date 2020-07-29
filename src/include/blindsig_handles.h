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

#ifndef _BLINDSIG_HANDLES_H
#define _BLINDSIG_HANDLES_H

#include "blindsig.h"
#include "groupsig/gl19/blindsig.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def GROUPSIG_BLINDSIG_HANDLES_N
 * @brief Number of supported set of handles for managing blinded group signatures.
 */
#define GROUPSIG_BLINDSIG_HANDLES_N 1

/**
 * @var GROUPSIG_BLINDSIG_HANDLES
 * @brief List of supported set of handles for managing blinded group signatures.
 */
static const groupsig_blindsig_handle_t *GROUPSIG_BLINDSIG_HANDLES[GROUPSIG_BLINDSIG_HANDLES_N] = { 
  &gl19_blindsig_handle,
};

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _BLINDSIG_HANDLES_H */

/* blindsig_handles.h ends here */
