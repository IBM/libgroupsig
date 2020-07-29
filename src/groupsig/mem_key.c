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

#include "mem_key_handles.h"
#include "key.h"
#include "logger.h"

const mem_key_handle_t* groupsig_mem_key_handle_from_code(uint8_t code) {

  int i;

  for(i=0; i<GROUPSIG_MEM_KEY_HANDLES_N; i++) {
    if(GROUPSIG_MEM_KEY_HANDLES[i]->code == code)
      return GROUPSIG_MEM_KEY_HANDLES[i];
  }

  return NULL;

}

groupsig_key_t* groupsig_mem_key_init(uint8_t code) {

  const mem_key_handle_t *gkh;

  if(!(gkh = groupsig_mem_key_handle_from_code(code))) {
    return NULL;
  }  

  return gkh->init();

}

int groupsig_mem_key_free(groupsig_key_t *key) {

  const mem_key_handle_t *gkh;

  if(!key) {
    LOG_EINVAL_MSG(&logger, __FILE__, "groupsig_mem_key_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if(!(gkh = groupsig_mem_key_handle_from_code(key->scheme))) {
    return IERROR;
  }
    
  gkh->free(key);
  
  return IOK;

}

int groupsig_mem_key_copy(groupsig_key_t *dst, groupsig_key_t *src) {

  const mem_key_handle_t *gkh;

  if(!dst || !src ||
     dst->scheme != src->scheme) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_mem_key_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(gkh = groupsig_mem_key_handle_from_code(dst->scheme))) {
    return IERROR;
  }

  return gkh->copy(dst, src);

}

int groupsig_mem_key_get_size(groupsig_key_t *key) {

  const mem_key_handle_t *gkh;

  if(!key) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_mem_key_get_size", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(gkh = groupsig_mem_key_handle_from_code(key->scheme))) {
    return IERROR;
  }

  return gkh->get_size(key);

}

int groupsig_mem_key_export(byte_t **dst,
			    uint32_t *size,
			    groupsig_key_t *key) {

  const mem_key_handle_t *gkh;

  if(!dst || !size || !key) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_mem_key_export", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(gkh = groupsig_mem_key_handle_from_code(key->scheme))) {
    return IERROR;
  }

  return gkh->gexport(dst, size, key);

}

groupsig_key_t* groupsig_mem_key_import(uint8_t code,
					byte_t *source,
					uint32_t size) {

  const mem_key_handle_t *gkh;

  if(!source) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_mem_key_import", __LINE__, LOGERROR);
    return NULL;
  }

  if(!(gkh = groupsig_mem_key_handle_from_code(code))) {
    return NULL;
  }

  return gkh->gimport(source, size);

}

char* groupsig_mem_key_to_string(groupsig_key_t *key) {

  const mem_key_handle_t *gkh;

  if(!key) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_mem_key_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  if(!(gkh = groupsig_mem_key_handle_from_code(key->scheme))) {
    return NULL;
  }

  return gkh->to_string(key);

}

/* mem_key.c ends here */
