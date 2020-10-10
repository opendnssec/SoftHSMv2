#include <config.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#ifdef _WIN32

extern "C" {

char *optarg;

int getopt(int argc, char * const argv[], const char *optstring) {
    return 0;
}


#endif
