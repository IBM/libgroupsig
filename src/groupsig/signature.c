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

#include "signature_handles.h"
#include "logger.h"

const groupsig_signature_handle_t* groupsig_signature_handle_from_code(uint8_t code) {

  int i;

  for(i=0; i<GROUPSIG_SIGNATURE_HANDLES_N; i++) {
    if(GROUPSIG_SIGNATURE_HANDLES[i]->scheme == code)
      return GROUPSIG_SIGNATURE_HANDLES[i];
  }

  return NULL;

}

groupsig_signature_t* groupsig_signature_init(uint8_t code) {

  const groupsig_signature_handle_t *gsh;

  if(!(gsh = groupsig_signature_handle_from_code(code))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_signature_init", __LINE__,
	       LOGERROR);
    return NULL;
  }

  return gsh->init();

}

int groupsig_signature_free(groupsig_signature_t *sig) {

  const groupsig_signature_handle_t *gsh;

  if(!sig) {
    LOG_EINVAL_MSG(&logger, __FILE__, "groupsig_signature_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }
  
  if(!(gsh = groupsig_signature_handle_from_code(sig->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_signature_free", __LINE__,
	       LOGERROR);
    return IERROR;
  }

  return gsh->free(sig);
  
}

int groupsig_signature_copy(groupsig_signature_t *dst, groupsig_signature_t *src) {

  const groupsig_signature_handle_t *gsh;

  if(!dst || !src ||
     dst->scheme != src->scheme) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_signature_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(gsh = groupsig_signature_handle_from_code(dst->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_signature_copy", __LINE__,
	       LOGERROR);
    return IERROR;
  }

  return gsh->copy(dst, src);

}

int groupsig_signature_get_size(groupsig_signature_t *sig) {

  const groupsig_signature_handle_t *gsh;

  if(!sig) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_signature_get_size_in_format", __LINE__,
	       LOGERROR);
    return IERROR;
  }

  if(!(gsh = groupsig_signature_handle_from_code(sig->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_signature_get_size_in_format", __LINE__,
	       LOGERROR);
    return IERROR;
  }

  return gsh->get_size(sig);

}


int groupsig_signature_export(byte_t **dst,
			      uint32_t *size,
			      groupsig_signature_t *sig) {

  const groupsig_signature_handle_t *gsh;

  if(!dst || !size || !sig) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_signature_export", __LINE__,
	       LOGERROR);
    return IERROR;
  }

  if(!(gsh = groupsig_signature_handle_from_code(sig->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_signature_export", __LINE__,
	       LOGERROR);
    return IERROR;
  }

  return gsh->gexport(dst, size, sig);

}

groupsig_signature_t* groupsig_signature_import(uint8_t code,
						byte_t *source,
						uint32_t size) {

  const groupsig_signature_handle_t *gsh;

  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_signature_import", __LINE__,
	       LOGERROR);
    return NULL;
  }

  if(!(gsh = groupsig_signature_handle_from_code(code))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_signature_import", __LINE__,
	       LOGERROR);
    return NULL;
  }

  return gsh->gimport(source, size);

}

char* groupsig_signature_to_string(groupsig_signature_t *sig) {

  const groupsig_signature_handle_t *gsh;

  if(!sig) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_signature_to_string", __LINE__,
	       LOGERROR);
    return NULL;
  }

  if(!(gsh = groupsig_signature_handle_from_code(sig->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_signature_to_string", __LINE__,
	       LOGERROR);
    return NULL;
  }

  return gsh->to_string(sig);

}


/* signature.c ends here */
