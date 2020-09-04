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
#include <errno.h>
#include <stdlib.h>

#include "ps16.h"
#include "groupsig/ps16/grp_key.h"
#include "groupsig/ps16/mem_key.h"
#include "sys/mem.h"
#include "crypto/spk.h"
#include "shim/pbc_ext.h"

/** 
 * In the paper, it is the member who begins the protocol and, during join,
 * an interactive ZK protocol is done where the member proves knowledge of
 * her secret exponent. Here, we replace this with having the protocol start
 * by the manager, who sends a fresh random number. Then, the member responds
 * with an SPK over that random number, where she also proves knowledge of
 * her secret exponent. This saves one message. 
 *
 * @TODO: This should not break security, but cross-check!
 *
 * Additionally, the PS16 scheme requires the member to have a previous
 * keypair+ccertificate from some "traditional" PKI system (e.g., an RSA/ECDSA 
 * certificate). During the join protocol, the member has to send a signature
 * of the value tau (see below, or the paper) under that keypair. IMHO, it makes
 * little sense to code that here, and it would be best to just "require" that
 * some external mechanism using a well tested PKI library is used for that.
 * Instead of signing tau, we can just sign the first message produced by the
 * member (which includes tau). 
 */
int ps16_join_mem(message_t **mout, groupsig_key_t *memkey,
		  int seq, message_t *min, groupsig_key_t *grpkey) {

  groupsig_key_t *_ps16_memkey;
  ps16_mem_key_t *ps16_memkey;
  ps16_grp_key_t *ps16_grpkey;
  spk_dlog_t *pi;
  pbcext_element_G1_t *n, *tau;
  pbcext_element_G2_t *ttau;
  message_t *_mout;
  byte_t *bn, *btau, *bttau, *bpi, *bmsg;
  uint64_t len, nlen, taulen, ttaulen, pilen;
  int rc;
  
  if(!memkey || memkey->scheme != GROUPSIG_PS16_CODE ||
     !min || (seq != 1 && seq != 3)) {
    LOG_EINVAL(&logger, __FILE__, "ps16_join_mem", __LINE__, LOGERROR);
    return IERROR;
  }

  ps16_memkey = memkey->key;
  ps16_grpkey = grpkey->key;
  _ps16_memkey = NULL;
  _mout = NULL;
  n = tau = NULL;
  ttau = NULL;
  pi = NULL;
  bn = btau = bttau = bpi = bmsg = NULL;
  rc = IOK;
  
  if (seq == 1) { /* First message of interactive protocol */

    /* The manager sends a random element in G1 */
    if(!(n = pbcext_element_G1_init()))
      GOTOENDRC(IERROR, ps16_join_mem);
    if(pbcext_get_element_G1_bytes(n, &nlen, min->bytes) == IERROR)
      GOTOENDRC(IERROR, ps16_join_mem);
    if(pbcext_element_G1_to_bytes(&bn, &nlen, n) == IERROR)
      GOTOENDRC(IERROR, ps16_join_mem);

    /* Compute secret exponent, tau and ttau */
    if(!(ps16_memkey->sk = pbcext_element_Fr_init()))
      GOTOENDRC(IERROR, ps16_join_mem);
    if(pbcext_element_Fr_random(ps16_memkey->sk) == IERROR)
      GOTOENDRC(IERROR, ps16_join_mem);
    if(!(tau = pbcext_element_G1_init())) GOTOENDRC(IERROR, ps16_join_mem);
    if(pbcext_element_G1_mul(tau, ps16_grpkey->g, ps16_memkey->sk) == IERROR)
      GOTOENDRC(IERROR, ps16_join_mem);
    if(!(ttau = pbcext_element_G2_init())) GOTOENDRC(IERROR, ps16_join_mem);
    if(pbcext_element_G2_mul(ttau, ps16_grpkey->Y, ps16_memkey->sk) == IERROR)
      GOTOENDRC(IERROR, ps16_join_mem);

    /* Compute the SPK for sk */
    if(!(pi = spk_dlog_init())) GOTOENDRC(IERROR, ps16_join_mem);
    if(spk_dlog_G1_sign(pi, tau,
			ps16_grpkey->g, ps16_memkey->sk, bn, nlen) == IERROR)
      GOTOENDRC(IERROR, ps16_join_mem);
    
    /* Need to send (n, tau, ttau, pi): prepare ad hoc message */
    mem_free(bn); bn = NULL;
    if (pbcext_dump_element_G1_bytes(&bn, &nlen, n) == IERROR)
      GOTOENDRC(IERROR, ps16_join_mem);
    len = nlen;
    
    if(pbcext_dump_element_G1_bytes(&btau,
				    &taulen,
				    tau) == IERROR) 
      GOTOENDRC(IERROR, ps16_join_mem);
    len += taulen;

    if(pbcext_dump_element_G2_bytes(&bttau,
				    &ttaulen,
				    ttau) == IERROR) 
      GOTOENDRC(IERROR, ps16_join_mem);
    len += ttaulen;
   
    if(spk_dlog_export(&bpi, &pilen, pi) == IERROR)
      GOTOENDRC(IERROR, ps16_join_mem);
    len += pilen;

    if(!(bmsg = (byte_t *) mem_malloc(sizeof(byte_t)*len)))
      GOTOENDRC(IERROR, ps16_join_mem);

    memcpy(bmsg, bn, nlen);
    memcpy(&bmsg[nlen], btau, taulen);
    memcpy(&bmsg[nlen+taulen], bttau, ttaulen);
    memcpy(&bmsg[nlen+taulen+ttaulen], bpi, pilen);

    if(!*mout) {
      if(!(_mout = message_from_bytes(bmsg, len)))
	GOTOENDRC(IERROR, ps16_join_mem);
      *mout = _mout;
    } else {
      _mout = *mout;
      if(message_set_bytes(*mout, bmsg, len) == IERROR)
	GOTOENDRC(IERROR, ps16_join_mem);
    }
    
  } else { /* Third (last) message of interactive protocol */

    /* We have sk in memkey, so just need to copy the
       sigma1, sigma2 and e values from the received message,
       which is an exported (partial) memkey */

    _ps16_memkey = ps16_mem_key_import(min->bytes, min->length);
    if (!_ps16_memkey) GOTOENDRC(IERROR, ps16_join_mem);

    if (ps16_mem_key_copy(memkey, _ps16_memkey) == IERROR)
      GOTOENDRC(IERROR, ps16_join_mem);

  }

 ps16_join_mem_end:

  if (rc == IERROR) {
    if (seq == 1) {
      if (ps16_memkey->sk) {
	pbcext_element_Fr_free(ps16_memkey->sk);
	ps16_memkey->sk = NULL;
      }
    }
  }

  if (_ps16_memkey) { ps16_mem_key_free(_ps16_memkey); _ps16_memkey = NULL; }
  if (pi) { spk_dlog_free(pi); pi = NULL; }
  if (n) { pbcext_element_G1_free(n); n = NULL; }
  if (tau) { pbcext_element_G1_free(tau); tau = NULL; }
  if (ttau) { pbcext_element_G2_free(ttau); ttau = NULL; }
  if (bn) {	mem_free(bn); bn = NULL; }      
  if (btau) { mem_free(btau); btau = NULL; }
  if (bttau) { mem_free(bttau); bttau = NULL; }
  if (bpi) { mem_free(bpi); bpi = NULL; }
  if (bmsg) { mem_free(bmsg); bmsg = NULL; }
    
  return rc;

}

/* join_mem.c ends here */
