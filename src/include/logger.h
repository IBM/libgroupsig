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

#ifndef _LOGGER_H
#define _LOGGER_H

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Constants definitions */

/**
 * @def DEFAULT_ERROR_LOG
 * @brief Default error log filename
 */
#define DEFAULT_ERROR_LOG "logger.log"

/**
 * @def LOGDEBUG
 * @brief Minimum level of priority. Prints all messages: Debug, Warning, and Error.
 */
#define LOGDEBUG 1

/**
 * @def LOGWARN
 * @brief Medium level of priority. Prints Warning and Error messages.
 */
#define LOGWARN 2

/**
 * @def LOGERROR
 * @brief Maximum level of priority. Prints only Error messages.
 */
#define LOGERROR 3

/* Macros */

/**
 * @def LOG_ERRORCODE 
 * @brief Expands to log_message(l, f, c, li, e, p); errno = e;
 */
#define LOG_ERRORCODE(l, f, c, li, e, p)	\
  errno = e;                                    \
  log_message(l, f, c, li, strerror(e), p);	\
  errno = e;

/**
 * @def LOG_ERRORCODE_MSG
 * @brief Expands to log_message(l, f, c, li, e, m, p); errno = e;
 */
#define LOG_ERRORCODE_MSG(l, f, c, li, e, m, p)	\
  errno = e;                                    \
  log_message(l, f, c, li, m, p);		\
  errno = e;

/**
 * @def LOG_EINVAL_MSG
 * @brief Expands to log_message(l, f, c, li, m, p); errno = EINVAL;
 */
#define LOG_EINVAL_MSG(l, f, c, li, m, p) \
  errno = EINVAL;                         \
  log_message(l, f, c, li, m, p);	  \
  errno = EINVAL;

/**
 * @def LOG_EINVAL
 * @brief Expands to log_message(l, f, c, li, strerror(EINVAL), p); errno = EINVAL;
 */
#define LOG_EINVAL(l, f, c, li, p)	  \
  errno = EINVAL;                         \
  log_message(l, f, c, li, strerror(EINVAL), p);	\
  errno = EINVAL;


/**
 * @struct log_t
 * @brief Log structure definition
 */
typedef struct {
  uint8_t initialized; /**< Boolean to mark logging initialized.*/
  char *filename; /**< Name of the file to write log messages in */
  FILE *fd;       /**< File descriptor for <i>filename</i> */
  uint8_t mode; /**< Working mode of the log. Any message with priority less
		     than mode won't be written in the log. */
  uint8_t verbosity;
  /* uint8_t stderrquiet; /\**< With critical errors, an error message will be */
  /* 			  shown in stderr unless the quiet flag is received *\/ */
} log_t;

/* Global variables  */

/**
 * @var logger
 * @brief Must be initialized in the main program (if logging support is desired).
 */
log_t logger;  

/* /\**  */
/*  * @var log_priority */
/*  * @brief Establishes the priority working mode of the library, and should be */
/*  *  initialised in the main program that uses the library. If not initalised */
/*  *  it's set to the maximum priority by default, meaning that only error */
/*  *  messages will be printed out. */
/*  *\/ */
/* uint8_t log_priority; */

/** 
 * @fn int log_init(char *filename, uint8_t mode, uint8_t quiet, log_t *log)
 * @brief Initializes <i>log</i> with the log file name <i>filename</i> and
 *  mode <i>mode</i>.
 *
 * @param[in] filename The log file name to use with this log.
 * @param[in] mode The working mode of the log. Any message with priority 
 *  lower than the log mode won't be written.
 * @param[in] verbosity Sets the desired verbosity of the log.
 * @param[in] log The log structure.
 * 
 * @return The corresponding error code for integer returning functions, i.e., 
 *  IOK if no error was present and IERROR if an error occured 
 *  with errno updated.
 * @retval IOK.
 * @retval IERROR. 
 */
int log_init(char *filename, uint8_t mode, uint8_t verbosity, log_t *log);

/** 
 * @fn int log_free(log_t *log)
 * @brief Frees the memory allocated in <i>log</i>.
 *
 * @param[in] log The log structure.
 * 
 * @return The corresponding error code for integer returning functions, i.e., 
 *  IOK if no error was present and IERROR if an error occured 
 *  with errno updated.
 * @retval IOK.
 * @retval IERROR. 
 */
int log_free(log_t *log);

/** 
 * @fn int log_message(log_t *log, const char *file, const char *caller, 
 *                     const char *message, int line, uint8_t priority)
 * 
 * @brief Writes <i>message</i> into the application log specified by 
 * <i>log</i>.
 *
 * Called by <i>caller</i> which may be (ideally) the caller function or whatever
 * the user wants, writes <i>message</i> using the configuration in <i>log</i>.
 * Before writing, evalautes the logging mode in <i>log</i> and the priority
 * of the message received. If the priority is equal or greater than the logging
 * mode, the message will be written, otherwise, it won't.
 * NOTE: This function DOES include a '\n' at the end of <i>message</i>.
 *
 * @param[in] log The logging structure.
 * @param[in] file The file to which the caller belongs to.
 * @param[in] caller The name of the caller (function, program or whatever).
 * @param[in] line The line where the logger is being called.
 * @param[in] message The message to write
 * @param[in] priority Message priority, useful when different logging modes
 *  are available (all, warnings, debug, none, ...)
 * 
 * @return The corresponding error code for integer returning functions, i.e., 
 *  IOK if no error was present and IERROR if an error occured 
 *  with errno updated.
 * @retval IOK.
 * @retval IERROR. 
 */
int log_message(log_t *log, const char *file, const char *caller, int line,
		const char *message, uint8_t priority);

/**
 * @fn int log_printf(log_t *log, uint8_t priority, const char *format, ...)
 * @brief Like fprintf, but prints <i>format</i> in the log file
 *
 * NOTE: This function DOES NOT include a '\n' at the end of <i>message</i>.
 *
 * @param[in] log The logger object
 * @param[in] priority The priority of the message. The message will only be 
 *  printed in the log file if it's priority is equal or greater than the log
 *  priority.
 * @param[in] format The format string to print
 * @param[in] ... The values for the placeholders in <i>format</i>, if any
 *
 * @return The corresponding error code for integer returning functions, i.e., 
 *  IOK if no error was present and IERROR if an error occured 
 *  with errno updated.
 * @retval IOK.
 * @retval IERROR. 
 */
int log_printf(log_t *log, uint8_t priority, const char *format, ...);

/**
 * @fn int log_printargs(log_t *log, const char *caller, uint8_t priority, 
 *                       char *argv[], int argc)
 * @brief Prints argv in the log
 *
 * @param[in] log The logger object
 * @param[in] caller The caller name
 * @param[in] priority The priority of the message. The message will only be 
 *  printed in the log file if it's priority is equal or greater than the log
 *  priority.
 * @param[in] argv The arguments to print
 * @param[in] argc Number of elements in argv
 *
 * @return The corresponding error code for integer returning functions, i.e., 
 *  IOK if no error was present and IERROR if an error occured 
 *  with errno updated.
 * @retval IOK.
 * @retval IERROR. 
 */
int log_printargs(log_t *log, const char *caller, uint8_t priority, char *argv[],
		  int argc);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Write any cplusplus specific code here */
#endif

#endif

/* logger.h ends here */
