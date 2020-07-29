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
#include "sys/mem.h"
#include "misc/misc.h"
#include "groupsig/cpy06/trapdoor.h"
#include "wrappers/pbc_ext.h"

trapdoor_t* cpy06_trapdoor_init() {
  
  trapdoor_t *trap;
  cpy06_trapdoor_t *cpy06_trap;
  
  if(!(trap = (trapdoor_t *) mem_malloc(sizeof(trapdoor_t)))) {
    return NULL;
  }

  if(!(cpy06_trap = (cpy06_trapdoor_t *) mem_malloc(sizeof(cpy06_trapdoor_t)))) {
    mem_free(trap); trap = NULL;
    return NULL;
  }
  
  /* The cpy06_trap->open field is of type element_t (pbc library) and the
     pairing is necessary to initialize it, hence, it must be initialized
     and set in the join_mgr function. */
  
  trap->scheme = GROUPSIG_CPY06_CODE;
  trap->trap = cpy06_trap;
  
  return trap;
  
}

int cpy06_trapdoor_free(trapdoor_t *trap) {
  
  cpy06_trapdoor_t *cpy06_trap;
  
  if(!trap || trap->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL_MSG(&logger, __FILE__, "cpy06_trapdoor_free", __LINE__,
		   "Nothing to free.", LOGWARN);
    return IOK;
  }

  if(trap->trap) {
    cpy06_trap = trap->trap;
    if(cpy06_trap->open[0].data) element_clear(cpy06_trap->open);
    if(cpy06_trap->trace[0].data) element_clear(cpy06_trap->trace);
    mem_free(cpy06_trap); cpy06_trap = NULL;
  }
  
  mem_free(trap);
  
  return IOK;
  
}

int cpy06_trapdoor_copy(trapdoor_t *dst, trapdoor_t *src) {
  
  if(!dst || dst->scheme != GROUPSIG_CPY06_CODE ||
     !src || src->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_trapdoor_copy", __LINE__, LOGERROR);
    return IERROR;
  }

  /* Open trapdoor */
  element_init_same_as(((cpy06_trapdoor_t *) dst->trap)->open,
		       ((cpy06_trapdoor_t *) src->trap)->open);

  element_set(((cpy06_trapdoor_t *) dst->trap)->open, 
	      ((cpy06_trapdoor_t *) src->trap)->open);  

  /* Trace trapdoor */
  element_init_same_as(((cpy06_trapdoor_t *) dst->trap)->trace,
		       ((cpy06_trapdoor_t *) src->trap)->trace);

  element_set(((cpy06_trapdoor_t *) dst->trap)->trace, 
	      ((cpy06_trapdoor_t *) src->trap)->trace);  


  return IOK;

}

char* cpy06_trapdoor_to_string(trapdoor_t *trap) {
  
  char *open_b64, *trace_b64, *b64;
  
  if(!trap || trap->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_trapdoor_to_string", __LINE__, LOGERROR);
    return NULL;
  }
  
  if(!(open_b64 = pbcext_element_export_b64(((cpy06_trapdoor_t *)trap->trap)->open))) {
    return NULL;
  }

  if(!(trace_b64 = pbcext_element_export_b64(((cpy06_trapdoor_t *)trap->trap)->trace))) {
    mem_free(open_b64); open_b64 = NULL;
    return NULL;
  }

  if(!(b64 = mem_malloc(sizeof(char *)*strlen(open_b64)+strlen(trace_b64)+2))) {
    mem_free(open_b64); open_b64 = NULL;
    mem_free(trace_b64); trace_b64 = NULL;
    return NULL;
  }
  
  sprintf(b64, "%s %s", open_b64, trace_b64);
  mem_free(open_b64); open_b64 = NULL;
  mem_free(trace_b64); trace_b64 = NULL;  

  return b64;
  
}

trapdoor_t* cpy06_trapdoor_from_string(char *strap) {
  
  trapdoor_t *trap;
  cpy06_sysenv_t *env;
  char *sopen, *strace;
  int rc;
  
  if(!strap) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_trapdoor_from_string", __LINE__, LOGERROR);
    return NULL;
  }
  
  /* Open trapdoors are the A elements of the member keys */
  env = (cpy06_sysenv_t *) sysenv->data;

  if(!(sopen = (char *) mem_malloc(sizeof(char)*strlen(strap)+1))) {
    return NULL;
  }

  if(!(strace = (char *) mem_malloc(sizeof(char)*strlen(strap)+1))) {
    mem_free(sopen); sopen = NULL;
    return NULL;
  }

  if((rc = sscanf(strap, "%s %s", sopen, strace)) == EOF) {
    LOG_ERRORCODE(&logger, __FILE__, "cpy06_trapdoor_from_string", __LINE__,
		  errno, LOGERROR);
    mem_free(sopen); sopen = NULL;
    mem_free(strace); strace = NULL;
    return NULL;
  }

  if(rc != 2) {
    LOG_ERRORCODE_MSG(&logger, __FILE__, "cpy06_trapdoor_from_string", __LINE__,
		      EDQUOT, "Corrupted or invalid trapdoor.", LOGERROR);
    mem_free(sopen); sopen = NULL;
    mem_free(strace); strace = NULL;
    return NULL;
  }

  if(!(trap = cpy06_trapdoor_init())) {
    mem_free(sopen); sopen = NULL;
    mem_free(strace); strace = NULL;
    return NULL;
  }

  element_init_G1(((cpy06_trapdoor_t *) trap->trap)->open, env->pairing);
  if(pbcext_element_import_b64(((cpy06_trapdoor_t *) trap->trap)->open, sopen) == IERROR) {
    mem_free(sopen); sopen = NULL;
    mem_free(strace); strace = NULL;
    cpy06_trapdoor_free(trap); trap = NULL;
    return NULL;
  }

  element_init_G1(((cpy06_trapdoor_t *) trap->trap)->trace, env->pairing);
  if(pbcext_element_import_b64(((cpy06_trapdoor_t *) trap->trap)->trace, strace) == IERROR) {
    mem_free(sopen); sopen = NULL;
    mem_free(strace); strace = NULL;
    cpy06_trapdoor_free(trap); trap = NULL;
    return NULL;
  }

  mem_free(sopen); sopen = NULL;
  mem_free(strace); strace = NULL;
  
  return trap;
  
}

int cpy06_trapdoor_cmp(trapdoor_t *t1, trapdoor_t *t2) {
  
  if(!t1 || t1->scheme != GROUPSIG_CPY06_CODE ||
     !t2 || t2->scheme != GROUPSIG_CPY06_CODE) {
    LOG_EINVAL(&logger, __FILE__, "cpy06_trapdoor_cmp", __LINE__, LOGERROR);
    return IERROR;
  }

  return element_cmp(((cpy06_trapdoor_t *)t1->trap)->open, 
		     ((cpy06_trapdoor_t *)t2->trap)->open);

}

/* identity.c ends here */
