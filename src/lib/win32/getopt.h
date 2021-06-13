#ifndef GETOPT_H
#define GETOPT_H

extern "C" {

extern char *optarg;

extern int getopt(int argc, char * const argv[], const char *optstring);

}

#endif
