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

#ifndef _TYPES_H
#define _TYPES_H

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Constants */

/* Application metadata */
/* /\** */
/*  * @def GROUPSIGNAME */
/*  * @brief Specifies the name of the software */
/*  *\/ */
/* #define GROUPSIGNAME "groupsigs" */

/* /\** */
/*  * @def GROUPSIGVERSION */
/*  * @brief Specifies the current version of the software. */
/*  *\/ */
/* #define GROUPSIGVERSION "0.0" */

/* /\** */
/*  * @def GROUPSIGCOPYRIGHT */
/*  * @brief Short copyright statement. */
/*  *\/ */
/* #define GROUPSIGCOPYRIGHT " " */

/**
 * @def IOK
 * @brief Integer return code for OK (execution successful).
 */
#define IOK 0

/**
 * @def IERROR
 * @brief Integer return code for ERROR (meaning that somehow, there was a malfunction). 
 *  When this code is returned, errno should be consequently set.
 */
#define IERROR 1

/**
 * @def IFAIL
 *  Integer return code for ERROR (execution failed). This code is used when a 
 *  function does not successfully accomplish its task, but not due to an 
 *  "unexpected error". E.g. if a parsing function does not return what it was
 *  supposed to find due to an EOF, instead of due to lack of memory. Usually,
 *  this code will be accompanied by a "reason" code.
 */
#define IFAIL 2

/**
 * @def IEXISTS
 * @brief Integer return code for functions that try to add something to a list (or 
 * similar) but find out that the received element already exists in the list.
 */
#define IEXISTS 3

/**
 * @def SHA1_DIGEST_LENGTH_DIGITS
 * @brief Number of decimal digits needed to represent a SHA1 digest as a decimal number.
 */
/* #define SHA1_DIGEST_LENGTH_DIGITS 49 */

/**
 * @def PRIMALITY_ITERS
 * @brief Sets the number of iterations to run in the primality tests.
 *  5 to 10 are the recommended number of iterations.
 */
#define PRIMALITY_ITERS 10

/**
 * @var MAX_GETRANDOM_ATTEMPTS
 * @brief Maximum attempts to call getrandom before failing.
 */
#define MAX_GETRANDOM_ATTEMPTS 10

/* Type definitions */

typedef unsigned char byte_t;

/* Macros */

/**
 * @def GOTOENDRC
 * @brief Useful for modifying return codes and redirecting to goto labels.
 */
#define GOTOENDRC(c, f)				\
  {						\
  rc = c;					\
  goto f ## _end;				\
  }

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif

/* types.h ends here */
