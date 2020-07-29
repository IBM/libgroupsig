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

#include <stdlib.h>

#include "types.h"
#include "logger.h"
#include "sys/mem.h"
#include "misc/misc.h"
#include "shim/pbc_ext.h"
#include "groupsig/gl19/identity.h"

identity_t* gl19_identity_init() {

  identity_t *id;
  gl19_identity_t *gl19_id;

  if(!(id = (identity_t *) mem_malloc(sizeof(identity_t)))) {
    LOG_ERRORCODE(&logger, __FILE__, "gl19_identity_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  if(!(gl19_id = (gl19_identity_t *) mem_malloc(sizeof(gl19_identity_t)))) {
    mem_free(id); id = NULL;
    LOG_ERRORCODE(&logger, __FILE__, "gl19_identity_init", __LINE__, errno, LOGERROR);
    return NULL;
  }

  id->scheme = GROUPSIG_GL19_CODE;
  id->id = gl19_id;
  
  return id;

}

int gl19_identity_free(identity_t *id) {

  gl19_identity_t *gl19_id;

  if(!id) {
    LOG_EINVAL_MSG(&logger, __FILE__, "gl19_identity_free", __LINE__,
  		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if(id->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_identity_free", __LINE__, LOGERROR);
    return IERROR;
  }

  gl19_id = id->id;
  pbcext_element_G1_free(gl19_id); gl19_id = NULL;
  mem_free(id);

  return IOK;

}

int gl19_identity_copy(identity_t *dst, identity_t *src) {

  gl19_identity_t *gl19_srcid, *gl19_dstid;
  
  if(!dst || dst->scheme != GROUPSIG_GL19_CODE ||
     !src || src->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_identity_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  gl19_srcid = src->id;
  gl19_dstid = dst->id;
  
  if(!(gl19_dstid = pbcext_element_G1_init())) return IERROR;
  if(pbcext_element_G1_set(gl19_dstid, gl19_srcid) == IERROR) return IERROR;
  
  return IOK;

}

uint8_t gl19_identity_cmp(identity_t *id1, identity_t *id2) {

  gl19_identity_t *gl19_id1, *gl19_id2;
  
  if(!id1 || !id2 || id1->scheme != id2->scheme || 
     id1->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_identity_cmp", __LINE__, LOGERROR);
    return UINT8_MAX;
  }

  gl19_id1 = id1->id;
  gl19_id2 = id2->id;

  return pbcext_element_G1_cmp(gl19_id1, gl19_id2);

}

char* gl19_identity_to_string(identity_t *id) {

  gl19_identity_t *gl19_id;
  char *s;
  
  if(!id || id->scheme != GROUPSIG_GL19_CODE) {
    LOG_EINVAL(&logger, __FILE__, "gl19_identity_to_string", __LINE__, LOGERROR);
    return NULL;
  }

  gl19_id = id->id;
  s = pbcext_element_G1_to_b64(gl19_id);

  return s;

}

identity_t* gl19_identity_from_string(char *sid) {

  /* identity_t *id; */
  /* uint64_t uid; */

  if(!sid) {
    LOG_EINVAL(&logger, __FILE__, "gl19_identity_from_string", __LINE__, LOGERROR);
    return NULL;
  }

  /* if(!(id = gl19_identity_init())) { */
  /*   return NULL; */
  /* } */

  /* /\* Currently, GL19 identities are uint64_t's *\/ */
  /* errno = 0; */
  /* uid = strtoul(sid, NULL, 10); */
  /* if(errno) { */
  /*   gl19_identity_free(id); */
  /*   return NULL; */
  /* } */

  /* *((gl19_identity_t *) id->id) = uid; */

  /* return id; */

  return NULL;

}

/* identity.c ends here */
