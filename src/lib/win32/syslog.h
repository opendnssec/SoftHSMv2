#ifndef _SYSLOG_H
#define _SYSLOG_H

#include <stdio.h>

/* priorities */
#define LOG_EMERG       0       /* system is unusable */
#define LOG_ALERT       1       /* action must be taken immediately */
#define LOG_CRIT        2       /* critical conditions */
#define LOG_ERR         3       /* error conditions */
#define LOG_WARNING     4       /* warning conditions */
#define LOG_NOTICE      5       /* normal but signification condition */
#define LOG_INFO        6       /* informational */
#define LOG_DEBUG       7       /* debug-level messages */

/* NT event log does not support facility level */
#define LOG_KERN	0
#define LOG_USER	0
#define LOG_MAIL	0
#define LOG_DAEMON	0
#define LOG_AUTH	0
#define LOG_SYSLOG	0
#define LOG_LPR		0
#define LOG_LOCAL0	0
#define LOG_LOCAL1	0
#define LOG_LOCAL2	0
#define LOG_LOCAL3	0
#define LOG_LOCAL4	0
#define LOG_LOCAL5	0
#define LOG_LOCAL6	0
#define LOG_LOCAL7	0

/* Constant definitions for openlog() */
#define LOG_PID		1
#define LOG_CONS	2

void
closelog(void);

void
openlog(const char *ident, int logopt, int facility);

void
syslog(int priority, const char *message, ...);

#endif
