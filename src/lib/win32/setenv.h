#include <config.h>

#ifdef _WIN32

#ifndef _SETENV_H
#define _SETENV_H

int setenv(const char *name, const char *value, int overwrite);

#endif

#endif