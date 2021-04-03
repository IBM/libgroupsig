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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <libgen.h>
#include <openssl/rand.h>

#include "groupsig.h"
#include "gml.h"
#include "crl.h"
#include "sysenv.h"
#include "logger.h"

#include "message.h"
#include "misc/misc.h"
#include "sys/mem.h"
#include "shim/base64.h"
#include "misc/profile.h"

log_t logger;
sysenv_t *sysenv;

static int
_do_setup
(
 int code,
 groupsig_key_t *grpkey,
 groupsig_key_t *mgrkey1,
 groupsig_key_t *mgrkey2,
 gml_t *gml
 ) {

  if (!grpkey || !mgrkey1 || !mgrkey2)
    return IERROR;

  switch(code) {
  case GROUPSIG_GL19_CODE:
    if (groupsig_setup(code, grpkey, mgrkey1, gml) == IERROR)
      return IERROR;
    if (groupsig_setup(code, grpkey, mgrkey2, gml) == IERROR)
      return IERROR;    
    break;
  case GROUPSIG_KLAP20_CODE:
    if (groupsig_setup(code, grpkey, mgrkey1, gml) == IERROR)
      return IERROR;
    if (groupsig_setup(code, grpkey, mgrkey2, gml) == IERROR)
      return IERROR;    
    break;    
  default:
    if (groupsig_setup(code, grpkey, mgrkey1, gml) == IERROR)
      return IERROR;
    break;
  }
  
}

static message_t*
_prepare_message()
{

  byte_t bmsg[500], bscp[500];
  char *smsg, *sscp, *str;
  message_t *msg;
  int msglen, scplen, strl, rc;

  smsg = sscp = str = NULL;
  msg = NULL;
  rc = IOK;
  
  memset(bmsg, 0, 500);
  memset(bscp, 0, 500);  
  
  msglen = (rand() % 500)+1;
  scplen = (rand() % 500)+1;  
  
  if (!RAND_bytes(bmsg, msglen))
    GOTOENDRC(IERROR, _prepare_message);

  if (!(smsg = base64_encode(bmsg, msglen, 0)))
    GOTOENDRC(IERROR, _prepare_message);

  if (!RAND_bytes(bscp, scplen))
    GOTOENDRC(IERROR, _prepare_message);

  if (!(sscp = base64_encode(bscp, scplen, 0)))
    GOTOENDRC(IERROR, _prepare_message);  

  strl = strlen(smsg) + strlen(sscp) + strlen("{ \"scope\": \"\", \"message\": \"\" }")+1;
  if (!(str = mem_malloc(sizeof(char)*strl)))
    GOTOENDRC(IERROR, _prepare_message);

  sprintf(str, "{ \"scope\": \"%s\", \"message\": \"%s\" }", sscp, smsg);
  if (!(msg = message_from_string(str)))
    GOTOENDRC(IERROR, _prepare_message);
  
 _prepare_message_end:

  if (smsg) { mem_free(smsg); smsg = NULL; }
  if (sscp) { mem_free(sscp); sscp = NULL; }
  if (str) { mem_free(str); str = NULL; }
  
  if (rc == IERROR) {
    if (msg) { message_free(msg); msg = NULL; }
  }
  
  return msg;
  
}

static int
_run_benchmark
(
 uint8_t code,
 char *filename,
 uint32_t iters,
 uint32_t batch
 ) {

  const groupsig_t *gh;
  groupsig_key_t *grpkey, *mgrkey1, *mgrkey2, *memkey;
  groupsig_key_t *bldkey;
  groupsig_signature_t *sig, *sigs[500];
  groupsig_blindsig_t *bsigs[500], *csigs[500];
  groupsig_proof_t *proof;
  message_t *mout, *min, *msg, *msgs[500];
  gml_t *gml;
  crl_t *crl;
  trapdoor_t *trap;
  identity_t *ids[500];
  FILE *fd;
  profile_t *prof_setup, *prof_join, *prof_sign, *prof_verify;
  profile_t *prof_open, *prof_open_verify, *prof_reveal, *prof_trace;
  profile_t *prof_claim, *prof_claim_verify;
  profile_t *prof_blind, *prof_convert, *prof_unblind;
  profile_t *prof_identify;
  profile_t *prof_link, *prof_verify_link;
  profile_t *prof_seqlink, *prof_verify_seqlink;  
  struct timeval tv_begin, tv_end;  
  clock_t clck_begin, clck_end;
  uint64_t index, cycle_begin, cycle_end;  
  uint32_t i, j;
  uint8_t start, seq, nmsgs, b;
  int rc;

  if (!filename || !iters || !batch) {
    fprintf(stderr, "_run_benchmark: wrong parameters.\n");
    return IERROR;
  }

  grpkey = NULL;
  mgrkey1 = mgrkey2 = NULL;
  bldkey = NULL;
  gml = NULL;
  crl = NULL;
  proof = NULL;
  trap = NULL;
  fd = NULL;
  prof_setup = prof_join = prof_sign = prof_verify = NULL;
  prof_open = prof_open_verify = prof_reveal = prof_trace = NULL;
  prof_claim = prof_claim_verify = NULL;
  prof_blind = prof_convert = prof_unblind = NULL;
  prof_identify = NULL;
  prof_link = prof_verify_link = NULL;
  prof_seqlink = prof_verify_seqlink = NULL;  
  rc = IOK;
  
  if (!(gh = groupsig_get_groupsig_from_code(code))) {
    return IERROR;
  }
  
  if (!(prof_setup = profile_begin(filename)))
    GOTOENDRC(IERROR, _run_benchmark);

  if (!(prof_join = profile_begin(filename)))
    GOTOENDRC(IERROR, _run_benchmark);

  if (!(prof_sign = profile_begin(filename)))
    GOTOENDRC(IERROR, _run_benchmark);

  if (!(prof_verify = profile_begin(filename)))
    GOTOENDRC(IERROR, _run_benchmark);

  if (!(prof_open = profile_begin(filename)))
    GOTOENDRC(IERROR, _run_benchmark);

  if (!(prof_open_verify = profile_begin(filename)))
    GOTOENDRC(IERROR, _run_benchmark);

  if (!(prof_reveal = profile_begin(filename)))
    GOTOENDRC(IERROR, _run_benchmark);

  if (!(prof_trace = profile_begin(filename)))
    GOTOENDRC(IERROR, _run_benchmark);

  if (!(prof_claim = profile_begin(filename)))
    GOTOENDRC(IERROR, _run_benchmark);

  if (!(prof_claim_verify = profile_begin(filename)))
    GOTOENDRC(IERROR, _run_benchmark);

  if (!(prof_blind = profile_begin(filename)))
    GOTOENDRC(IERROR, _run_benchmark);  

  if (!(prof_convert = profile_begin(filename)))
    GOTOENDRC(IERROR, _run_benchmark);  

  if (!(prof_unblind = profile_begin(filename)))
    GOTOENDRC(IERROR, _run_benchmark);

  if (!(prof_identify = profile_begin(filename)))
    GOTOENDRC(IERROR, _run_benchmark);  

  if (!(prof_link = profile_begin(filename)))
    GOTOENDRC(IERROR, _run_benchmark);  

  if (!(prof_verify_link = profile_begin(filename)))
    GOTOENDRC(IERROR, _run_benchmark);

  if (!(prof_seqlink = profile_begin(filename)))
    GOTOENDRC(IERROR, _run_benchmark);  

  if (!(prof_verify_seqlink = profile_begin(filename)))
    GOTOENDRC(IERROR, _run_benchmark);  
  
  for (i=0; i<iters; i++) {

    if (!(grpkey = groupsig_grp_key_init(code)))
      GOTOENDRC(IERROR, _run_benchmark);
    
    if (!(mgrkey1 = groupsig_mgr_key_init(code)))
      GOTOENDRC(IERROR, _run_benchmark);

    if (!(mgrkey2 = groupsig_mgr_key_init(code)))
      GOTOENDRC(IERROR, _run_benchmark);    

    if(!(memkey = groupsig_mem_key_init(code)))
      GOTOENDRC(IERROR, _run_benchmark);

    memset(bsigs, 0, sizeof(groupsig_blindsig_t *)*500);
    memset(csigs, 0, sizeof(groupsig_blindsig_t *)*500);
    memset(sigs, 0, sizeof(groupsig_signature_t *)*500);  
    memset(msgs, 0, sizeof(message_t *)*500);
    memset(ids, 0, sizeof(identity_t *)*500);    
    
    if (gh->desc->has_gml)
      if (!(gml = gml_init(code)))
	GOTOENDRC(IERROR, _run_benchmark);

    if (profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);
    
    if (_do_setup(code, grpkey, mgrkey1, mgrkey2, gml) == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);

    if (profile_get_time(&tv_end, &clck_end, &cycle_end) == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);

    if (profile_add_entry(prof_setup,
			  &tv_begin, &tv_end,
			  clck_begin, clck_end,
			  cycle_begin, cycle_end) == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);

    if(groupsig_get_joinstart(code, &start) == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);      

    if(groupsig_get_joinseq(code, &nmsgs) == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);      

    seq = 0;
    min = NULL; mout = NULL;

    if (profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);    
    
    /* The manager starts */
    if(!start) {

      while (seq <= nmsgs) {

	if(groupsig_join_mgr(&mout, gml, mgrkey1, seq, min, grpkey) == IERROR)
	  GOTOENDRC(IERROR, _run_benchmark);
	
	if (min) { message_free(min); min = NULL; }
	min = mout; mout = NULL;
	seq++;

	if(seq > nmsgs) break;

	if(groupsig_join_mem(&mout, memkey, seq, min, grpkey) == IERROR)
	  GOTOENDRC(IERROR, _run_benchmark);
	
	if (min) { message_free(min); min = NULL; }
	min = mout; mout = NULL;
	seq++;

      }
 
    } else { /* The member starts */

      while (seq <= nmsgs) {

	if(groupsig_join_mem(&mout, memkey, seq, min, grpkey) == IERROR)
	  GOTOENDRC(IERROR, _run_benchmark);
	
	if (min) { message_free(min); min = NULL; }
	min = mout; mout = NULL;
	seq++;
	
	if(seq > nmsgs) break;
	
	if(groupsig_join_mgr(&mout, gml, mgrkey1, seq, min, grpkey) == IERROR)
	  GOTOENDRC(IERROR, _run_benchmark);
	
	if (min) { message_free(min); min = NULL; }
	min = mout; mout = NULL;
	seq++;

      }      
      
    }

    if (profile_get_time(&tv_end, &clck_end, &cycle_end) == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);

    if (profile_add_entry(prof_join,
			  &tv_begin, &tv_end,
			  clck_begin, clck_end,
			  cycle_begin, cycle_end) == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);    

    if (!(msg = _prepare_message()))
      GOTOENDRC(IERROR, _run_benchmark);

    if(!(sig = groupsig_signature_init(code)))
      GOTOENDRC(IERROR, _run_benchmark);

    if (profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);
    
    if(groupsig_sign(sig, msg, memkey, grpkey, UINT_MAX) == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);

    if (profile_get_time(&tv_end, &clck_end, &cycle_end) == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);

    if (profile_add_entry(prof_sign,
			  &tv_begin, &tv_end,
			  clck_begin, clck_end,
			  cycle_begin, cycle_end) == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);
    
    if (profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);
    
    if (groupsig_verify(&b, sig, msg, grpkey) == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);
    if (!b) GOTOENDRC(IERROR, _run_benchmark);    

    if (profile_get_time(&tv_end, &clck_end, &cycle_end) == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);

    if (profile_add_entry(prof_verify,
			  &tv_begin, &tv_end,
			  clck_begin, clck_end,
			  cycle_begin, cycle_end) == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);    

    if (gh->desc->has_open_proof) 
      if (!(proof = groupsig_proof_init(code)))
	GOTOENDRC(IERROR, _run_benchmark);

    if (gh->desc->has_crl)
      if (!(crl = crl_init(code)))
	GOTOENDRC(IERROR, _run_benchmark);

    if (gh->open) {
      if (profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);    

      if (gh->desc->inspector_key == 1) {
	if (groupsig_open(&index, proof, crl, sig, grpkey, mgrkey1, gml) == IERROR)
	  GOTOENDRC(IERROR, _run_benchmark);
      } else {
	if (groupsig_open(&index, proof, crl, sig, grpkey, mgrkey2, gml) == IERROR)
	  GOTOENDRC(IERROR, _run_benchmark);      
      }
    
      if (profile_get_time(&tv_end, &clck_end, &cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);

      if (profile_add_entry(prof_open,
			    &tv_begin, &tv_end,
			    clck_begin, clck_end,
			    cycle_begin, cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);

    }

    if (gh->desc->has_open_proof) {
      
      if (profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);    
      
      if (groupsig_open_verify(&b, proof, sig, grpkey) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);
      if (!b) GOTOENDRC(IERROR, _run_benchmark);      
      
      if (profile_get_time(&tv_end, &clck_end, &cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);
      
      if (profile_add_entry(prof_open_verify,
			    &tv_begin, &tv_end,
			    clck_begin, clck_end,
			    cycle_begin, cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);
      
    }

    if (gh->reveal) {
      
      if (profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);
      
      if (!(trap = trapdoor_init(code)))
	GOTOENDRC(IERROR, _run_benchmark);

      index = rand() % gml->n;
      
      if (groupsig_reveal(trap, crl, gml, index) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);
	
      if (profile_get_time(&tv_end, &clck_end, &cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);
	
      if (profile_add_entry(prof_reveal,
			    &tv_begin, &tv_end,
			    clck_begin, clck_end,
			    cycle_begin, cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);
	
    }

    if (gh->trace) {

      if (profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);

      if (gh->desc->inspector_key == 1) {
	if (groupsig_trace(&b, sig, grpkey, crl, mgrkey1, gml) == IERROR)
	  GOTOENDRC(IERROR, _run_benchmark);
	if (!b) GOTOENDRC(IERROR, _run_benchmark);	
      } else {	
	if (groupsig_trace(&b, sig, grpkey, crl, mgrkey2, gml) == IERROR)
	  GOTOENDRC(IERROR, _run_benchmark);
	if (!b) GOTOENDRC(IERROR, _run_benchmark);	
      }
      
      if (profile_get_time(&tv_end, &clck_end, &cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);
	
      if (profile_add_entry(prof_trace,
			    &tv_begin, &tv_end,
			    clck_begin, clck_end,
			    cycle_begin, cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);	
	
    }

    if (gh->claim) {

      if (profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);      

      if (groupsig_claim(proof, memkey, grpkey, sig) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);

      if (profile_get_time(&tv_end, &clck_end, &cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);
	
      if (profile_add_entry(prof_claim,
			    &tv_begin, &tv_end,
			    clck_begin, clck_end,
			    cycle_begin, cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);
      
    }
    
    if (gh->claim_verify) {

      if (profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);      
      
      if (groupsig_claim_verify(&b, proof, sig, grpkey) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);

      if (!b) GOTOENDRC(IERROR, _run_benchmark);      

      if (profile_get_time(&tv_end, &clck_end, &cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);
	
      if (profile_add_entry(prof_claim_verify,
			    &tv_begin, &tv_end,
			    clck_begin, clck_end,
			    cycle_begin, cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);
      
    }

    if (gh->blind) {

      bldkey = NULL;

      for (j=0; j<batch; j++) {

	if (msgs[j]) { message_free(msgs[j]); msgs[j] = NULL; }
	if (!(msgs[j] = _prepare_message()))
	  GOTOENDRC(IERROR, _run_benchmark);

	if(!(sigs[j] = groupsig_signature_init(code)))
	  GOTOENDRC(IERROR, _run_benchmark);

	if(groupsig_sign(sigs[j], msgs[j], memkey, grpkey, UINT_MAX) == IERROR)
	  GOTOENDRC(IERROR, _run_benchmark);
	
	if (!(bsigs[j] = groupsig_blindsig_init(code)))
	  GOTOENDRC(IERROR, _run_benchmark);

	if (profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR)
	  GOTOENDRC(IERROR, _run_benchmark);
	
	if (groupsig_blind(bsigs[j], &bldkey, grpkey, sigs[j], msgs[j]) == IERROR)
	  GOTOENDRC(IERROR, _run_benchmark);
	
	if (profile_get_time(&tv_end, &clck_end, &cycle_end) == IERROR)
	  GOTOENDRC(IERROR, _run_benchmark);
	
	if (profile_add_entry(prof_blind,
			      &tv_begin, &tv_end,
			      clck_begin, clck_end,
			      cycle_begin, cycle_end) == IERROR)
	  GOTOENDRC(IERROR, _run_benchmark);

      }
      
    }

    if (gh->convert) {

      for (j=0; j<batch; j++)
	if (!(csigs[j] = groupsig_blindsig_init(code)))
	  GOTOENDRC(IERROR, _run_benchmark);

      if (profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);

      if (gh->desc->inspector_key == 1) {
	if (groupsig_convert(csigs, bsigs, batch, grpkey, mgrkey1,
			     bldkey, NULL) == IERROR)
	  GOTOENDRC(IERROR, _run_benchmark);
      } else {
	if (groupsig_convert(csigs, bsigs, batch, grpkey, mgrkey2,
			     bldkey, NULL) == IERROR)
	  GOTOENDRC(IERROR, _run_benchmark);
      }
      
      if (profile_get_time(&tv_end, &clck_end, &cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);
	
      if (profile_add_entry(prof_convert,
			    &tv_begin, &tv_end,
			    clck_begin, clck_end,
			    cycle_begin, cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);

    }

    if (gh->unblind) {

      for (j=0; j<batch; j++) {

	if (msgs[j]) { message_free(msgs[j]); msgs[j] = NULL; }
	if (!(msgs[j] = message_init()))
	  GOTOENDRC(IERROR, _run_benchmark);

	if (!(ids[j] = identity_init(code)))
	  GOTOENDRC(IERROR, _run_benchmark);
	
	if (profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR)
	  GOTOENDRC(IERROR, _run_benchmark);
	
	if (groupsig_unblind(ids[j], sigs[j], bsigs[j],
			     grpkey, bldkey, msgs[j]) == IERROR)
	  GOTOENDRC(IERROR, _run_benchmark);
	
	if (profile_get_time(&tv_end, &clck_end, &cycle_end) == IERROR)
	  GOTOENDRC(IERROR, _run_benchmark);
	
	if (profile_add_entry(prof_unblind,
			      &tv_begin, &tv_end,
			      clck_begin, clck_end,
			      cycle_begin, cycle_end) == IERROR)
	  GOTOENDRC(IERROR, _run_benchmark);

      }
      
    }

    if (gh->identify) {

      if (profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);      

      if (groupsig_identify(&b, NULL, memkey, grpkey, sig, msg) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);

      if (profile_get_time(&tv_end, &clck_end, &cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);
	
      if (profile_add_entry(prof_identify,
			    &tv_begin, &tv_end,
			    clck_begin, clck_end,
			    cycle_begin, cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);
      
    }    

    if (gh->link) {

      for (j=0; j<batch; j++) {
	
	if (msgs[j]) { message_free(msgs[j]); msgs[j] = NULL; }
	if (!(msgs[j] = _prepare_message()))
	  GOTOENDRC(IERROR, _run_benchmark);
	if (sigs[j]) { groupsig_signature_free(sigs[j]); sigs[j] = NULL; }
	if (!(sigs[j] = groupsig_signature_init(code)))
	  GOTOENDRC(IERROR, _run_benchmark);
	if(groupsig_sign(sigs[j], msgs[j], memkey, grpkey, UINT_MAX) == IERROR)
	  GOTOENDRC(IERROR, _run_benchmark);	
      }
      
      if (profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);      

      if (proof) { groupsig_proof_free(proof); proof = NULL; }
      proof = NULL;
      if (groupsig_link(&proof, grpkey, memkey, msg, sigs, msgs, batch) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);

      if (profile_get_time(&tv_end, &clck_end, &cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);      
	
      if (profile_add_entry(prof_link,
			    &tv_begin, &tv_end,
			    clck_begin, clck_end,
			    cycle_begin, cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);      

    }

    if (gh->verify_link) {

      if (profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);      

      if (groupsig_verify_link(&b, grpkey, proof, msg, sigs, msgs, batch) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);

      if (!b) GOTOENDRC(IERROR, _run_benchmark);

      if (profile_get_time(&tv_end, &clck_end, &cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);      
	
      if (profile_add_entry(prof_verify_link,
			    &tv_begin, &tv_end,
			    clck_begin, clck_end,
			    cycle_begin, cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);      

    }

    if (gh->seqlink) {

      for (j=0; j<batch; j++) {
	
	if (msgs[j]) { message_free(msgs[j]); msgs[j] = NULL; }
	if (!(msgs[j] = _prepare_message()))
	  GOTOENDRC(IERROR, _run_benchmark);
	if (sigs[j]) { groupsig_signature_free(sigs[j]); sigs[j] = NULL; }
	if (!(sigs[j] = groupsig_signature_init(code)))
	  GOTOENDRC(IERROR, _run_benchmark);
	if(groupsig_sign(sigs[j], msgs[j], memkey, grpkey, j) == IERROR)
	  GOTOENDRC(IERROR, _run_benchmark);	
      }
      
      if (profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);      

      if (proof) { groupsig_proof_free(proof); proof = NULL; }
      proof = NULL;
      if (groupsig_seqlink(&proof, grpkey, memkey, msg, sigs, msgs, batch) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);

      if (profile_get_time(&tv_end, &clck_end, &cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);      
	
      if (profile_add_entry(prof_seqlink,
			    &tv_begin, &tv_end,
			    clck_begin, clck_end,
			    cycle_begin, cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);      

    }

    if (gh->verify_seqlink) {

      if (profile_get_time(&tv_begin, &clck_begin, &cycle_begin) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);      

      if (groupsig_verify_seqlink(&b, grpkey, proof, msg, sigs, msgs, batch) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);

      if (!b) GOTOENDRC(IERROR, _run_benchmark);

      if (profile_get_time(&tv_end, &clck_end, &cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);      
	
      if (profile_add_entry(prof_verify_seqlink,
			    &tv_begin, &tv_end,
			    clck_begin, clck_end,
			    cycle_begin, cycle_end) == IERROR)
	GOTOENDRC(IERROR, _run_benchmark);      

    }   
    
    for (j=0; j<batch; j++) {
      if (msgs[j]) { message_free(msgs[j]); msgs[j] = NULL; }
      if (sigs[j]) { groupsig_signature_free(sigs[j]); sigs[j] = NULL; }
      if (bsigs[j]) { groupsig_blindsig_free(bsigs[j]); bsigs[j] = NULL; }
      if (csigs[j]) { groupsig_blindsig_free(csigs[j]); csigs[j] = NULL; }
      if (ids[j]) { identity_free(ids[j]); ids[j] = NULL; }
    }
    if (trap) { trapdoor_free(trap); trap = NULL; }
    if (proof) { groupsig_proof_free(proof); proof = NULL; }
    if (sig) { groupsig_signature_free(sig); sig = NULL; }
    if (grpkey) { groupsig_grp_key_free(grpkey); grpkey = NULL; }    
    if (memkey) { groupsig_mem_key_free(memkey); memkey = NULL; }
    if (mgrkey1) { groupsig_mgr_key_free(mgrkey1); mgrkey1 = NULL; }
    if (mgrkey2) { groupsig_mgr_key_free(mgrkey2); mgrkey2 = NULL; }
    if (bldkey) { groupsig_bld_key_free(bldkey); bldkey = NULL; }      
    if (gml && gh->desc->has_gml) { gml_free(gml); gml = NULL; }
    if (crl && gh->desc->has_crl) { crl_free(crl); crl = NULL; }      
    if (min) { message_free(min); min = NULL; }
    if (mout) { message_free(mout); mout = NULL; }
    if (msg) { message_free(msg); msg = NULL; }    
           
  }

  if (profile_process_and_dump(prof_setup, code, "setup") == IERROR)
    GOTOENDRC(IERROR, _run_benchmark);  

  if (profile_process_and_dump(prof_join, code, "join") == IERROR)
    GOTOENDRC(IERROR, _run_benchmark);  

  if (profile_process_and_dump(prof_sign, code, "sign") == IERROR)
    GOTOENDRC(IERROR, _run_benchmark);
  
  if (profile_process_and_dump(prof_verify, code, "verify") == IERROR)
    GOTOENDRC(IERROR, _run_benchmark);

  if (gh->open) {
    if (profile_process_and_dump(prof_open, code, "open") == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);  
  } else {
    if (!(fd = fopen(filename, "a"))) GOTOENDRC(IERROR, _run_benchmark);
    fprintf(fd, "%s\topen\t0\t0\t0\t0\n", groupsig_get_name_from_code(code));
    fclose(fd); fd = NULL;
  }
  
  if (gh->open_verify) {
    if (profile_process_and_dump(prof_open_verify, code, "open_verify") == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);
  } else {
    if (!(fd = fopen(filename, "a"))) GOTOENDRC(IERROR, _run_benchmark);
    fprintf(fd, "%s\topen_verify\t0\t0\t0\t0\n", groupsig_get_name_from_code(code));
    fclose(fd); fd = NULL;
  }
  
  if (gh->reveal) {
    if (profile_process_and_dump(prof_reveal, code, "reveal") == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);
  } else {
    if (!(fd = fopen(filename, "a"))) GOTOENDRC(IERROR, _run_benchmark);
    fprintf(fd, "%s\treveal\t0\t0\t0\t0\n", groupsig_get_name_from_code(code));
    fclose(fd); fd = NULL;
  }
  
  if (gh->trace) {
    if (profile_process_and_dump(prof_trace, code, "trace") == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);
  } else {
    if (!(fd = fopen(filename, "a"))) GOTOENDRC(IERROR, _run_benchmark);
    fprintf(fd, "%s\ttrace\t0\t0\t0\t0\n", groupsig_get_name_from_code(code));
    fclose(fd); fd = NULL;
  }
  
  if (gh->claim) {
    if (profile_process_and_dump(prof_claim, code, "claim") == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);
  } else {
    if (!(fd = fopen(filename, "a"))) GOTOENDRC(IERROR, _run_benchmark);
    fprintf(fd, "%s\tclaim\t0\t0\t0\t0\n", groupsig_get_name_from_code(code));
    fclose(fd); fd = NULL;
  }
  
  if (gh->claim_verify) {
    if (profile_process_and_dump(prof_claim_verify, code, "claim_verify") == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);
  } else {
    if (!(fd = fopen(filename, "a"))) GOTOENDRC(IERROR, _run_benchmark);
    fprintf(fd, "%s\tclaim_verify\t0\t0\t0\t0\n", groupsig_get_name_from_code(code));
    fclose(fd); fd = NULL;
  }
  
  if (gh->blind) {
    if (profile_process_and_dump(prof_blind, code, "blind") == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);
  } else {
    if (!(fd = fopen(filename, "a"))) GOTOENDRC(IERROR, _run_benchmark);
    fprintf(fd, "%s\tblind\t0\t0\t0\t0\n", groupsig_get_name_from_code(code));
    fclose(fd); fd = NULL;
  }
  
  if (gh->convert) {
    if (profile_process_and_dump(prof_convert, code, "convert") == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);
  } else {
    if (!(fd = fopen(filename, "a"))) GOTOENDRC(IERROR, _run_benchmark);
    fprintf(fd, "%s\tconvert\t0\t0\t0\t0\n", groupsig_get_name_from_code(code));
    fclose(fd); fd = NULL;
  }
  
  if (gh->unblind) {
    if (profile_process_and_dump(prof_unblind, code, "unblind") == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);
  } else {
    if (!(fd = fopen(filename, "a"))) GOTOENDRC(IERROR, _run_benchmark);
    fprintf(fd, "%s\tunblind\t0\t0\t0\t0\n", groupsig_get_name_from_code(code));
    fclose(fd); fd = NULL;
  }
 
  if (gh->identify) {
    if (profile_process_and_dump(prof_identify, code, "identify") == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);  
  } else {
    if (!(fd = fopen(filename, "a"))) GOTOENDRC(IERROR, _run_benchmark);
    fprintf(fd, "%s\tidentify\t0\t0\t0\t0\n", groupsig_get_name_from_code(code));
    fclose(fd); fd = NULL;
  }
  
  if (gh->link) {
    if (profile_process_and_dump(prof_link, code, "link") == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);
  } else {
    if (!(fd = fopen(filename, "a"))) GOTOENDRC(IERROR, _run_benchmark);
    fprintf(fd, "%s\tlink\t0\t0\t0\t0\n", groupsig_get_name_from_code(code));
    fclose(fd); fd = NULL;
  }
  
  if (gh->verify_link) {
    if (profile_process_and_dump(prof_verify_link, code, "verify_link") == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);
  } else {
    if (!(fd = fopen(filename, "a"))) GOTOENDRC(IERROR, _run_benchmark);
    fprintf(fd, "%s\tverify_link\t0\t0\t0\t0\n", groupsig_get_name_from_code(code));
    fclose(fd); fd = NULL;
  }

  if (gh->seqlink) {
    if (profile_process_and_dump(prof_link, code, "seqlink") == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);
  } else {
    if (!(fd = fopen(filename, "a"))) GOTOENDRC(IERROR, _run_benchmark);
    fprintf(fd, "%s\tseqlink\t0\t0\t0\t0\n", groupsig_get_name_from_code(code));
    fclose(fd); fd = NULL;
  }
  
  if (gh->verify_seqlink) {
    if (profile_process_and_dump(prof_verify_link, code, "verify_seqlink") == IERROR)
      GOTOENDRC(IERROR, _run_benchmark);  
  } else {
    if (!(fd = fopen(filename, "a"))) GOTOENDRC(IERROR, _run_benchmark);
    fprintf(fd, "%s\tverify_seqlink\t0\t0\t0\t0\n", groupsig_get_name_from_code(code));
    fclose(fd); fd = NULL;
  }
  
 _run_benchmark_end:

  for (j=0; j<batch; j++) {
    if (msgs[j]) { message_free(msgs[j]); msgs[j] = NULL; }
    if (sigs[j]) { groupsig_signature_free(sigs[j]); sigs[j] = NULL; }
    if (bsigs[j]) { groupsig_blindsig_free(bsigs[j]); bsigs[j] = NULL; }
    if (csigs[j]) { groupsig_blindsig_free(csigs[j]); csigs[j] = NULL; }
    if (ids[j]) { identity_free(ids[j]); ids[j] = NULL; }    
  }  
  if (trap) { trapdoor_free(trap); trap = NULL; }
  if (proof) { groupsig_proof_free(proof); proof = NULL; }
  if (sig) { groupsig_signature_free(sig); sig = NULL; }  
  if (grpkey) { groupsig_grp_key_free(grpkey); grpkey = NULL; }
  if (mgrkey1) { groupsig_mgr_key_free(mgrkey1); mgrkey1 = NULL; }
  if (mgrkey2) { groupsig_mgr_key_free(mgrkey2); mgrkey2 = NULL; }  
  if (memkey) { groupsig_mem_key_free(memkey); memkey = NULL; }
  if (gml && gh->desc->has_gml) { gml_free(gml); gml = NULL; }
  if (crl && gh->desc->has_crl) { crl_free(crl); crl = NULL; }  
  if (prof_setup) { profile_free(prof_setup); prof_setup = NULL; }
  if (prof_join) { profile_free(prof_join); prof_join = NULL; }
  if (prof_sign) { profile_free(prof_sign); prof_sign = NULL; }
  if (prof_verify) { profile_free(prof_verify); prof_verify = NULL; }
  if (prof_open) { profile_free(prof_open); prof_open = NULL; }
  if (prof_open_verify) { profile_free(prof_open_verify); prof_open_verify = NULL; }
  if (prof_reveal) { profile_free(prof_reveal); prof_reveal = NULL; }
  if (prof_trace) { profile_free(prof_trace); prof_trace = NULL; }
  if (prof_claim) { profile_free(prof_claim); prof_claim = NULL; }
  if (prof_claim_verify) { profile_free(prof_claim_verify); prof_claim_verify = NULL; }
  if (prof_blind) { profile_free(prof_blind); prof_blind = NULL; }
  if (prof_convert) { profile_free(prof_convert); prof_convert = NULL; }
  if (prof_unblind) { profile_free(prof_unblind); prof_unblind = NULL; }
  if (prof_identify) { profile_free(prof_identify); prof_identify = NULL; }
  if (prof_link) { profile_free(prof_link); prof_link = NULL; }
  if (prof_verify_link) { profile_free(prof_verify_link); prof_verify_link = NULL; }
  if (prof_seqlink) { profile_free(prof_seqlink); prof_seqlink = NULL; }
  if (prof_verify_seqlink) { profile_free(prof_verify_seqlink); prof_verify_seqlink = NULL; }
  if (min) { message_free(min); min = NULL; }
  if (mout) { message_free(mout); mout = NULL; }
  if (msg) { message_free(msg); msg = NULL; }  
  
  return rc;
  
}

int main(int argc, char *argv[]) {
  
  char *filename;
  FILE *fd;
  uint64_t uint64;
  uint32_t iters, batch;
  uint8_t code;

  if(argc == 1) {
    fprintf(stdout, "Usage: %s <iters> <batch size> <output file>\n",
	    basename(argv[0]));
    return IOK;
  }

  /* Number of iterations to do per operation */
  errno = 0;
  uint64 = strtoul(argv[1], NULL, 10);
  if(errno || uint64 > UINT32_MAX) {
    fprintf(stderr, "Error: parsing iters.\n");
    return IERROR;
  }
  iters = (uint32_t) uint64;

  /* For schemes that do operations with baches of signatures (e.g., batched
     verification, link, convert...) batches will be of the specified size */
  errno = 0;
  uint64 = strtoul(argv[2], NULL, 10);
  if(errno || uint64 > UINT32_MAX) {
    fprintf(stderr, "Error: parsing batch size.\n");
    return IERROR;
  }
  if (uint64 > 500) {
    fprintf(stderr, "Error: batches cannot be larger than 500.\n");
    return IERROR;
  }
  batch = (uint32_t) uint64;  
  

  /* 
     Iterate through the codes of the supported schemes.
     This is very dirty, but there is currently no way to retrieve the codes of 
     all supported schemes. Change if one becomes available.
  */
  filename = argv[3];

  fd = fopen(filename, "a");
  if (!fd) {
    return IERROR;
  }

  fprintf(fd,
	  "#Times are in microseconds\n"
	  "#scheme\toperation\tavg user time\tstd user time\tavg cpu time\tstd cpu time\n");
  fclose(fd); fd = NULL;
  
  
  for (code=0; code<UINT8_MAX; code++) {
    
    if (!groupsig_is_supported_scheme(code)) continue;

      if (groupsig_init(code, 0) == IERROR) {
	fprintf(stderr, "Error initializing scheme with code %u\n", code);
	return IERROR;
      }

      if (_run_benchmark(code, filename, iters, batch) == IERROR) {
	fprintf(stderr, "Error benchmarking scheme with code %u\n",
		code);
	return IERROR;
      }

      if (groupsig_clear(code) == IERROR) {
	fprintf(stderr, "Error clearing scheme with code %u\n", code);
	return IERROR;
      }

  }

  return IOK;
  
}

/* benchmarks.c ends here */
