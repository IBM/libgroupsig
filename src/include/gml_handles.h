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

#ifndef _GML_HANDLES_H
#define _GML_HANDLES_H

#include "gml.h"
/* #include "groupsig/kty04/gml.h" */
#include "groupsig/bbs04/gml.h"
/* #include "groupsig/cpy06/gml.h" */
#include "groupsig/ps16/gml.h"
#include "groupsig/klap20/gml.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @def GML_HANDLES_N
 * @brief Number of known GML implementation handles.
 */
#define GML_HANDLES_N 3

/**
 * @var GML_HANDLES
 * @brief Set of handles of known GML implementations.
 */
const gml_handle_t *GML_HANDLES[GML_HANDLES_N] = {
  /* &kty04_gml_handle, */
  &bbs04_gml_handle,
  /* &cpy06_gml_handle, */
  &ps16_gml_handle,
  &klap20_gml_handle,
};

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif
  
#endif /* _GML_HANDLES_H */

/* gml_handles.h ends here */
