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

#include "sys/mem.h"
#include "bbs04.h"

int bbs04_claim(groupsig_proof_t *proof, groupsig_key_t *memkey, 
		groupsig_key_t *grpkey, groupsig_signature_t *sig) {

  /* groupsig_signature_t **sigs; */
  /* int rc; */

  /* if(!proof || proof->scheme != GROUPSIG_BBS04_CODE || */
  /*    !memkey || memkey->scheme != GROUPSIG_BBS04_CODE || */
  /*    !grpkey || grpkey->scheme != GROUPSIG_BBS04_CODE || */
  /*    !sig || sig->scheme != GROUPSIG_BBS04_CODE) { */
  /*   LOG_EINVAL(&logger, __FILE__, "bbs04_claim", __LINE__, LOGERROR); */
  /*   return IERROR; */
  /* } */

  /* /\* A claim is just similar to proving "equality" of N sigature, but just  */
  /*    for 1 signature *\/ */
  /* if(!(sigs = (groupsig_signature_t **) mem_malloc(sizeof(groupsig_signature_t *)))) { */
  /*   LOG_ERRORCODE(&logger, __FILE__, "bbs04_claim", __LINE__, errno, LOGERROR); */
  /*   return IERROR; */
  /* } */

  /* sigs[0] = sig; */

  /* rc = bbs04_prove_equality(proof, memkey, grpkey, sigs, 1); */
  /* mem_free(sigs); sigs = NULL; */

  /* return rc; */

  return IOK;
  
}

/* claim.c ends here */
