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

#ifndef _PERM_H
#define _PERM_H

#include "types.h"

/** 
 * @fn int perm_durstenfeld_inplace_int(void **array, int size);
 * @brief Uses Durstenfeld variant of the Fisher-Yates in place permutation 
 *  algorithm to output a random permutation of the given array.
 *
 * See https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle#The_modern_algorithm
 * for a definition of the algorithm.
 * 
 * @param[in,out] array The array of pointers to permute.
 * @param[in] size The number of elements in the array.
 * 
 * @return IOK or IERROR
 */
int perm_durstenfeld_inplace(void **array, int size);

#endif

/* perm.h ends here */
