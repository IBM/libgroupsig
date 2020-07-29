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

#include "blindsig_handles.h"
#include "logger.h"

const groupsig_blindsig_handle_t* groupsig_blindsig_handle_from_code(uint8_t code) {

  int i;

  for(i=0; i<GROUPSIG_BLINDSIG_HANDLES_N; i++) {
    if(GROUPSIG_BLINDSIG_HANDLES[i]->scheme == code)
      return GROUPSIG_BLINDSIG_HANDLES[i];
  }

  return NULL;

}

groupsig_blindsig_t* groupsig_blindsig_init(uint8_t code) {

  const groupsig_blindsig_handle_t *gsh;

  if(!(gsh = groupsig_blindsig_handle_from_code(code))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_blindsig_init", __LINE__,
	       LOGERROR);
    return NULL;
  }

  return gsh->init();

}

int groupsig_blindsig_free(groupsig_blindsig_t *sig) {

  const groupsig_blindsig_handle_t *gsh;

  if(!sig) {
    LOG_EINVAL_MSG(&logger, __FILE__, "groupsig_blindsig_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }
  
  if(!(gsh = groupsig_blindsig_handle_from_code(sig->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_blindsig_free", __LINE__,
	       LOGERROR);
    return IERROR;
  }

  return gsh->free(sig);
  
}

int groupsig_blindsig_copy(groupsig_blindsig_t *dst, groupsig_blindsig_t *src) {

  const groupsig_blindsig_handle_t *gsh;

  if(!dst || !src ||
     dst->scheme != src->scheme) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_blindsig_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(gsh = groupsig_blindsig_handle_from_code(dst->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_blindsig_copy", __LINE__,
	       LOGERROR);
    return IERROR;
  }

  return gsh->copy(dst, src);

}

int groupsig_blindsig_get_size(groupsig_blindsig_t *sig) {

  const groupsig_blindsig_handle_t *gsh;

  if(!sig) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_blindsig_get_size", __LINE__,
	       LOGERROR);
    return IERROR;
  }

  if(!(gsh = groupsig_blindsig_handle_from_code(sig->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_blindsig_get_size", __LINE__,
	       LOGERROR);
    return IERROR;
  }

  return gsh->get_size(sig);

}


int groupsig_blindsig_export(byte_t **dst,
			     uint32_t *size,
			     groupsig_blindsig_t *sig) {

  const groupsig_blindsig_handle_t *gsh;

  if(!dst || !size || !sig) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_blindsig_export", __LINE__,
	       LOGERROR);
    return IERROR;
  }

  if(!(gsh = groupsig_blindsig_handle_from_code(sig->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_blindsig_export", __LINE__,
	       LOGERROR);
    return IERROR;
  }

  return gsh->gexport(dst, size, sig);

}

groupsig_blindsig_t* groupsig_blindsig_import(uint8_t code,
					      byte_t *source,
					      uint32_t size) {

  const groupsig_blindsig_handle_t *gsh;

  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_blindsig_import", __LINE__,
	       LOGERROR);
    return NULL;
  }

  if(!(gsh = groupsig_blindsig_handle_from_code(code))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_blindsig_import", __LINE__,
	       LOGERROR);
    return NULL;
  }

  return gsh->gimport(source, size);

}

char* groupsig_blindsig_to_string(groupsig_blindsig_t *sig) {

  const groupsig_blindsig_handle_t *gsh;

  if(!sig) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_blindsig_to_string", __LINE__,
	       LOGERROR);
    return NULL;
  }

  if(!(gsh = groupsig_blindsig_handle_from_code(sig->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_blindsig_to_string", __LINE__,
	       LOGERROR);
    return NULL;
  }

  return gsh->to_string(sig);

}


/* blindsig.c ends here */
