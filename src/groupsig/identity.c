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

#include "identity_handles.h"
#include "logger.h"

const identity_handle_t* identity_handle_from_code(uint8_t code) {

  int i;

  for(i=0; i<IDENTITY_HANDLES_N; i++) {
    if(code == IDENTITY_HANDLES[i]->scheme) 
      return IDENTITY_HANDLES[i];
  }

  return NULL;

}

identity_t* identity_init(uint8_t code) {

  const identity_handle_t *idh;

  if(!(idh = identity_handle_from_code(code))) {
    LOG_EINVAL(&logger, __FILE__, "identity_init", __LINE__, LOGERROR);
    return NULL;
  }

  return idh->init();

}

int identity_free(identity_t *id) {

  const identity_handle_t *idh;

  if(!(idh = identity_handle_from_code(id->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "identity_free", __LINE__, LOGERROR);
    return IERROR;
  }

  return idh->free(id);

}

int identity_copy(identity_t *dst, identity_t *src) {

  const identity_handle_t *idh;

  if(dst->scheme != src->scheme) {
    LOG_EINVAL(&logger, __FILE__, "identity_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(idh = identity_handle_from_code(dst->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "identity_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  return idh->copy(dst, src);

}

uint8_t identity_cmp(identity_t *id1, identity_t *id2) {

 const identity_handle_t *idh;

 if(!id1 || !id2 || id1->scheme != id2->scheme) {
   LOG_EINVAL(&logger, __FILE__, "identity_cmp", __LINE__, LOGERROR);
   return UINT8_MAX;
 }

  if(!(idh = identity_handle_from_code(id1->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "identity_cmp", __LINE__, LOGERROR);
    return UINT8_MAX;
  }

  return idh->cmp(id1, id2);

}

char* identity_to_string(identity_t *id) {

  const identity_handle_t *idh;

  if(!(idh = identity_handle_from_code(id->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "identity_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  return idh->to_string(id);

}

identity_t* identity_from_string(uint8_t code, char *sid) {

  const identity_handle_t *idh;

  if(!(idh = identity_handle_from_code(code))) {
    LOG_EINVAL(&logger, __FILE__, "identity_from_string", __LINE__, LOGERROR);
    return NULL;
  }

  return idh->from_string(sid);

}


/* identity.c ends here */
