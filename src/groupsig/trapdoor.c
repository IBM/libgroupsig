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

#include "logger.h"
#include "types.h"
#include "trapdoor_handles.h"

const trapdoor_handle_t* trapdoor_handle_from_code(uint8_t code) {

  int i;

  for(i=0; i<TRAPDOOR_HANDLES_N; i++) {
    if(code == TRAPDOOR_HANDLES[i]->scheme) 
      return TRAPDOOR_HANDLES[i];
  }

  return NULL;

}

trapdoor_t* trapdoor_init(uint8_t code) {

  const trapdoor_handle_t *tdh;

  if(!(tdh = trapdoor_handle_from_code(code))) {
    LOG_EINVAL(&logger, __FILE__, "trapdoor_init", __LINE__, LOGERROR);
    return NULL;
  }

  return tdh->init();

}

int trapdoor_free(trapdoor_t *trap) {

  const trapdoor_handle_t *tdh;

  if(!(tdh = trapdoor_handle_from_code(trap->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "trapdoor_free", __LINE__, LOGERROR);
    return IERROR;
  }

  return tdh->free(trap);

}

int trapdoor_copy(trapdoor_t *dst, trapdoor_t *src) {

  const trapdoor_handle_t *tdh;

  if(dst->scheme != src->scheme) {
    LOG_EINVAL(&logger, __FILE__, "trapdoor_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(tdh = trapdoor_handle_from_code(dst->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "trapdoor_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  return tdh->copy(dst, src);

}

char* trapdoor_to_string(trapdoor_t *trap) {

  const trapdoor_handle_t *tdh;

  if(!(tdh = trapdoor_handle_from_code(trap->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "trapdoor_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  return tdh->to_string(trap);

}

trapdoor_t* trapdoor_from_string(uint8_t code, char *strap) {

  const trapdoor_handle_t *tdh;

  if(!(tdh = trapdoor_handle_from_code(code))) {
    LOG_EINVAL(&logger, __FILE__, "trapdoor_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  return tdh->from_string(strap);

}

/* trapdoor.c ends here */
