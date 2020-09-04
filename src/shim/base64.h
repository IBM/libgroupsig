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

#ifndef _BASE64_H
#define _BASE64_H

#include <stdint.h>
#include "types.h"

/** 
 * @fn char* base64_encode(const byte_t *in, uint64_t length, uint8_t nl)
 * @brief Base64-encodes the specified byte array.
 *
 * @param[in] in The byte array to encode.
 * @param[in] length The number of bytes in <i>in</i>.
 * @param[in] nl If 0, no line feeds will be added every 72 chars nor
 *  at the end of the resulting string. Else, they will.
 * 
 * @return A pointer to the resulting Base64 string, or NULL if error.
 */
char* base64_encode(const byte_t *in, uint64_t length, uint8_t nl);

/** 
 * @fn byte_t* base64_decode(const char *in, uint64_t *length_dec)
 * @brief Decodes the given Base64 encoded string.
 *
 * @param[in] in The Base64 string to decode.
 * @param[in,out] length_dec Will be set to the size of the decoded byte array.
 * 
 * @return A pointer to the decoded byte array.
 */
byte_t* base64_decode(const char *in, uint64_t *length_dec);

#endif /* _BASE64_H */

/* base64.h ends here */
