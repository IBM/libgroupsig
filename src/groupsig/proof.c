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

#include "proof_handles.h"
#include "logger.h"

const groupsig_proof_handle_t* groupsig_proof_handle_from_code(uint8_t code) {

  int i;

  for(i=0; i<GROUPSIG_PROOF_HANDLES_N; i++) {
    if(code == GROUPSIG_PROOF_HANDLES[i]->scheme) {
      return GROUPSIG_PROOF_HANDLES[i];
    }
  }

  return NULL;

}


groupsig_proof_t* groupsig_proof_init(uint8_t code) {

  const groupsig_proof_handle_t *gph;

  if(!(gph = groupsig_proof_handle_from_code(code))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_proof_init", __LINE__,
	       LOGERROR);
    return NULL;
  }

  return gph->init();

}

int groupsig_proof_free(groupsig_proof_t *proof) {

  const groupsig_proof_handle_t *gph;

  if(!proof) {
    LOG_EINVAL_MSG(&logger, __FILE__, "groupsig_proof_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }
  
  if(!(gph = groupsig_proof_handle_from_code(proof->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_proof_free", __LINE__,
	       LOGERROR);
    return IERROR;
  }

  return gph->free(proof);
  
}

int groupsig_proof_get_size(groupsig_proof_t *proof) {

  const groupsig_proof_handle_t *gph;

  if(!proof) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_proof_get_size_in_format", __LINE__,
	       LOGERROR);
    return IERROR;
  }
  
  if(!(gph = groupsig_proof_handle_from_code(proof->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_proof_get_size_in_format", __LINE__,
	       LOGERROR);
    return IERROR;
  }

  return gph->get_size(proof);

}

int groupsig_proof_copy(groupsig_proof_t *dst, groupsig_proof_t *src) {

  const groupsig_proof_handle_t *gsh;

  if(!dst || !src ||
     dst->scheme != src->scheme) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_proof_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  if(!(gsh = groupsig_proof_handle_from_code(dst->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_proof_copy", __LINE__,
	       LOGERROR);
    return IERROR;
  }

  return gsh->copy(dst, src);

}

int groupsig_proof_export(byte_t **bytes,
			  uint32_t *size,
			  groupsig_proof_t *proof) {

  const groupsig_proof_handle_t *gph;

  if(!bytes || !size || !proof) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_proof_export", __LINE__,
	       LOGERROR);
    return IERROR;
  }
  
  if(!(gph = groupsig_proof_handle_from_code(proof->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_proof_export", __LINE__,
	       LOGERROR);
    return IERROR;
  }

  return gph->gexport(bytes, size, proof);

}

groupsig_proof_t* groupsig_proof_import(uint8_t code, 
					byte_t *source,
					uint32_t size) {

  const groupsig_proof_handle_t *gph;

  if(!source || !size) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_proof_import", __LINE__,
	       LOGERROR);
    return NULL;
  }

  if(!(gph = groupsig_proof_handle_from_code(code))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_proof_import", __LINE__,
	       LOGERROR);
    return NULL;
  }

  return gph->gimport(source, size);

}

char* groupsig_proof_to_string(groupsig_proof_t *proof) {

  const groupsig_proof_handle_t *gph;

  if(!proof) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_proof_to_string", __LINE__,
	       LOGERROR);
    return NULL;
  }

  if(!(gph = groupsig_proof_handle_from_code(proof->scheme))) {
    LOG_EINVAL(&logger, __FILE__, "groupsig_proof_to_string", __LINE__,
	       LOGERROR);
    return NULL;
  }

  return gph->to_string(proof);

}

/* proof.c ends here */
