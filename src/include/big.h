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

#ifndef _BIG_H
#define _BIG_H

#include <openssl/bn.h>

#ifdef __cplusplus
extern "C" {
#endif

  /**
   * OpenSSL's BIGNUM operations usually require a BN_CTX
   * structure. This will be initialized by groupsig_init, which
   * needs to be executed before using the library, and freed
   * by groupsig_clear.
   */
  typedef BN_CTX *big_ctx_t;
  
  /**
   * Big Integer type definition.
   */
  typedef BIGNUM *bigz_t;//mpz_t *bigz_t;

  /**
   * Big Float type definition.
   */
  //typedef mpf_t *bigf_t;

  /**
   * Random state definition.
   */
  //typedef gmp_randstate_t bigz_randstate_t;
  
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif /* _BIG_H */

/* big.h ends here */
