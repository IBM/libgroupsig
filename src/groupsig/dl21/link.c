/*                               -*- Mode: C -*- 
 *
 *	libgroupsig Group Signatures library
 *	Copyright (C) 2012-2013 Jesus Diaz Vico
 *
 *		
 *
 *	This file is part of the libgroupsig Group Signatures library.
 *
 *
 *  The libgroupsig library is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License as 
 *  defined by the Free Software Foundation, either version 3 of the License, 
 *  or any later version.
 *
 *  The libroupsig library is distributed WITHOUT ANY WARRANTY; without even 
 *  the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  
 *  See the GNU Lesser General Public License for more details.
 *
 *
 *  You should have received a copy of the GNU Lesser General Public License 
 *  along with Group Signature Crypto Library.  If not, see <http://www.gnu.org/
 *  licenses/>
 *
 * @file: blind.c
 * @brief: 
 * @author: jesus
 * Maintainer: 
 * @date: lun jun 11 12:53:13 2012 (+0200)
 * @version: 
 * Last-Updated: lun ago  5 15:10:56 2013 (+0200)
 *           By: jesus
 *     Update #: 4
 * URL: 
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "types.h"
#include "sysenv.h"
#include "bigz.h"
#include "sys/mem.h"
#include "dl21.h"
#include "groupsig/dl21/grp_key.h"
#include "groupsig/dl21/mem_key.h"
#include "groupsig/dl21/signature.h"
#include "groupsig/dl21/identity.h"
#include "groupsig/dl21/proof.h"
#include "shim/hash.h"
#include "shim/pbc_ext.h"

int dl21_link(groupsig_proof_t **proof,
	      groupsig_key_t *grpkey,
	      groupsig_key_t *memkey,
	      message_t *msg,
	      groupsig_signature_t **sigs,
	      message_t **msgs,
	      uint32_t n) {
  
  pbcext_element_G1_t *hscp, *hscp_, *nym_;
  dl21_signature_t *dl21_sig;
  dl21_mem_key_t *dl21_memkey;
  /* dl21_sysenv_t *dl21_sysenv; */
  groupsig_proof_t *_proof;
  spk_dlog_t *spk;
  hash_t *hc;
  char *msg_scp, *msg_msg;
  int rc;
  uint32_t i;
  uint8_t ok;

  if(!proof ||
     !grpkey || grpkey->scheme != GROUPSIG_DL21_CODE ||
     !memkey || memkey->scheme != GROUPSIG_DL21_CODE ||
     !msg || !sigs || !msgs || !n) {
    LOG_EINVAL(&logger, __FILE__, "dl21_link", __LINE__, LOGERROR);
    return IERROR;
  }

  rc = IOK;
  hscp = NULL; hscp_ = NULL; nym_ = NULL;
  hc = NULL;
  msg_scp = NULL; msg_msg = NULL;
  
  dl21_memkey = memkey->key;

  if(!(hscp = pbcext_element_G1_init())) GOTOENDRC(IERROR, dl21_link);
  if(!(hscp_ = pbcext_element_G1_init())) GOTOENDRC(IERROR, dl21_link);
  if(pbcext_element_G1_clear(hscp_) == IERROR) GOTOENDRC(IERROR, dl21_link);
  if(!(nym_ = pbcext_element_G1_init())) GOTOENDRC(IERROR, dl21_link);
  if(pbcext_element_G1_clear(nym_) == IERROR) GOTOENDRC(IERROR, dl21_link);

  /* Iterate through all signatures, verify, identify and
     compute batched scope and nym */
  for (i=0; i<n; i++ ) {

    /* Verify signature */
    if (dl21_verify(&ok, sigs[i], msgs[i], grpkey) == IERROR)
      GOTOENDRC(IERROR, dl21_link);
    if (!ok) GOTOENDRC(IFAIL, dl21_link);
    
    /* Check if it is a signature issued by memkey */
    if (dl21_identify(&ok, NULL, grpkey, memkey, sigs[i], msgs[i]) == IERROR)
      GOTOENDRC(IERROR, dl21_link);
    
    if (!ok) {
      GOTOENDRC(IFAIL, dl21_link);
    }
    
    /* "Accumulate" scp */
    if(message_json_get_key(&msg_scp, msgs[i], "$.scope") == IERROR)
      GOTOENDRC(IERROR, dl21_link);

    if(!(hc = hash_init(HASH_SHA1))) GOTOENDRC(IERROR, dl21_link);
    if(hash_update(hc, (byte_t *) msg_scp, strlen(msg_scp)) == IERROR)
      GOTOENDRC(IERROR, dl21_link);
    if(hash_finalize(hc) == IERROR) GOTOENDRC(IERROR, dl21_link);
    pbcext_element_G1_from_hash(hscp, hc->hash, hc->length);
    hash_free(hc); hc = NULL;
    mem_free(msg_scp); msg_scp = NULL;
    
    if(pbcext_element_G1_add(hscp_, hscp_, hscp) == IERROR)
      GOTOENDRC(IERROR, dl21_link);

  }

  /* nym_ = hscp_^y */
  if(pbcext_element_G1_mul(nym_, hscp_, dl21_memkey->y) == IERROR)
    GOTOENDRC(IERROR, dl21_link);

  /* Do the SPK */

  // For now, we just use the .msg part of the msg JSON, but
  // the .scp part might come in handy in the future
  if(message_json_get_key(&msg_msg, msg, "$.message") == IERROR)
    GOTOENDRC(IERROR, dl21_link);  

  if(!(_proof = dl21_proof_init())) GOTOENDRC(IERROR, dl21_link);
  spk = _proof->proof;

  if(spk_dlog_G1_sign(spk, nym_, hscp_, dl21_memkey->y, (byte_t *) msg_msg,
		      strlen(msg_msg)) == IERROR) GOTOENDRC(IERROR, dl21_link);
  *proof = _proof;

 dl21_link_end:

  if(msg_msg) { mem_free(msg_msg); msg_msg = NULL; }
  if(hscp) { pbcext_element_G1_free(hscp); hscp = NULL; }
  if(hscp_) { pbcext_element_G1_free(hscp_); hscp_ = NULL; }  
  if(nym_) { pbcext_element_G1_free(nym_); nym_ = NULL; }
  if(hc) { hash_free(hc); hc = NULL; }

  return rc;

}

/* link.c ends here */
