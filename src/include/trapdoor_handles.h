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

#ifndef _TRAPDOOR_HANDLES_H
#define _TRAPDOOR_HANDLES_H

#include "string.h"
#include "trapdoor.h"
/* #include "groupsig/kty04/trapdoor.h" */
/* #include "groupsig/cpy06/trapdoor.h" */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def TRAPDOOR_HANDLES_N
 * @brief Number of supported trapdoors.
 */
#define TRAPDOOR_HANDLES_N 1//3

/**
 * @var TRAPDOOR_HANDLES
 * @brief List of supported trapdoors.
 */
static const trapdoor_handle_t *TRAPDOOR_HANDLES[TRAPDOOR_HANDLES_N] = {
  //  &kty04_trapdoor_handle,
  //  &cpy06_trapdoor_handle,
  NULL,
};

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif
  
#endif /* _TRAPDOOR_HANDLES_H */

/* trapdoor_handles.h ends here */
