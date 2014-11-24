/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/************************************************************
*
* softhsm2-keyconv
*
* This program is for converting from BIND .private-key
* format to PKCS#8 key file format. So that keys can be
* imported from BIND to SoftHSM.
*
* Some of the design/code is from keyconv.c written by
* Hakan Olsson and Jakob Schlyter in 2000 and 2001.
*
************************************************************/

#include <config.h>
#include "softhsm2-keyconv.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#else
#include <io.h>
#define S_IRUSR 0400
#define S_IWUSR 0200
#define open _open
#define close _close
#endif
#include <iostream>
#include <fstream>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

void usage()
{
	printf("Converting from BIND .private-key format to PKCS#8 key file format.\n");
	printf("Usage: softhsm2-keyconv [OPTIONS]\n");
	printf("Options:\n");
	printf("  -h                  Shows this help screen.\n");
	printf("  --help              Shows this help screen.\n");
	printf("  --in <path>         The path to the input file.\n");
	printf("  --out <path>        The path to the output file.\n");
	printf("  --pin <PIN>         To encrypt PKCS#8 file. Optional.\n");
	printf("  -v                  Show version info.\n");
	printf("  --version           Show version info.\n");
}

// Give a number to each option
enum {
	OPT_HELP = 0x100,
	OPT_IN,
	OPT_OUT,
	OPT_PIN,
	OPT_VERSION
};

// Define the options
static const struct option long_options[] = {
	{ "help",    0, NULL, OPT_HELP },
	{ "in",      1, NULL, OPT_IN },
	{ "out",     1, NULL, OPT_OUT },
	{ "pin",     1, NULL, OPT_PIN },
	{ "version", 0, NULL, OPT_VERSION },
	{ NULL,      0, NULL, 0 }
};

int main(int argc, char* argv[])
{
	int option_index = 0;
	int opt, result;

	char* in_path = NULL;
	char* out_path = NULL;
	char* file_pin = NULL;

	if (argc == 1)
	{
		usage();
		exit(0);
	}

	while ((opt = getopt_long(argc, argv, "hv", long_options, &option_index)) != -1)
	{
		switch (opt)
		{
			case OPT_IN:
				in_path = optarg;
				break;
			case OPT_OUT:
				out_path = optarg;
				break;
			case OPT_PIN:
				file_pin = optarg;
				break;
			case OPT_VERSION:
			case 'v':
				printf("%s\n", PACKAGE_VERSION);
				exit(0);
				break;
			case OPT_HELP:
			case 'h':
			default:
				usage();
				exit(0);
				break;
		}
	}

	// We should convert to PKCS#8
	result = to_pkcs8(in_path, out_path, file_pin);

	return result;
}

// Convert from BIND to PKCS#8
int to_pkcs8(char* in_path, char* out_path, char* file_pin)
{
	FILE* file_pointer = NULL;
	char line[MAX_LINE], data[MAX_LINE];
	char* value_pointer = NULL;
	int lineno = 0, m, n, error = 0, found, algorithm = DNS_KEYALG_ERROR, data_length;
	uint32_t bitfield = 0;
	key_material_t pkey[TAG_MAX];

	if (in_path == NULL)
	{
		fprintf(stderr, "ERROR: A path to the input file must be supplied. Use --in <path>\n");
		return 1;
	}

	if (out_path == NULL)
	{
		fprintf(stderr, "ERROR: A path to the output file must be supplied. Use --out <path>\n");
		return 1;
	}

	file_pointer = fopen(in_path, "r");
	if (file_pointer == NULL)
	{
		fprintf(stderr, "ERROR: Could not open input file %.100s for reading.\n", in_path);
		return 1;
	}

	// Loop over all of the lines
	while (fgets(line, MAX_LINE, file_pointer) != NULL)
	{
		lineno++;

		// Find the current text field in the BIND file.
		for (m = 0, found = -1; found == -1 && file_tags[m]; m++)
		{
			if (strncasecmp(line, file_tags[m], strlen(file_tags[m])) == 0)
			{
				found = m;
			}
		}

		// The text files is not recognized.
		if (found == -1)
		{
			fprintf(stderr, "ERROR: Unrecognized input line %i\n", lineno);
			fprintf(stderr, "ERROR: --> %s", line);
			continue;
		}

		// Point to the data for this text field.
		value_pointer = line + strlen(file_tags[found]) + 1;

		// Continue if we are at the end of the string
		if (*value_pointer == 0)
		{
			continue;
		}

		// Check that we do not get duplicates.
		if (bitfield & (1 << found))
		{
			fprintf(stderr, "ERROR: Duplicate \"%s\" field, line %i - ignored\n",
					file_tags[found], lineno);
			continue;
		}
		bitfield |= (1 << found);

		// Handle the data for this text field.
		switch (found)
		{
			case TAG_VERSION:
				if (sscanf(value_pointer, "v%i.%i", &m, &n) != 2)
				{
					fprintf(stderr, "ERROR: Invalid/unknown version string "
							"(%.100s).\n", value_pointer);
					error = 1;
					break;
				}
				if (m > FILE_MAJOR_VERSION || (m == FILE_MAJOR_VERSION && n > FILE_MINOR_VERSION))
				{
					fprintf(stderr, "ERROR: Cannot parse this version of file format, "
							"v%i.%i.\n", m, n);
					error = 1;
				}
				break;
			case TAG_ALGORITHM:
				algorithm = strtol(value_pointer, NULL, 10);
				break;
			// RSA
			case TAG_MODULUS:
			case TAG_PUBEXP:
			case TAG_PRIVEXP:
			case TAG_PRIME1:
			case TAG_PRIME2:
			case TAG_EXP1:
			case TAG_EXP2:
			case TAG_COEFF:
			// DSA
			case TAG_PRIME:
			case TAG_SUBPRIME:
			case TAG_BASE:
			case TAG_PRIVVAL:
			case TAG_PUBVAL:
				data_length = b64_pton(value_pointer, (unsigned char*)data, MAX_LINE);
				if (data_length == -1)
				{
					error = 1;
					fprintf(stderr, "ERROR: Could not parse the base64 string on line %i.\n", lineno);
				}
				else
				{
					pkey[found].big = malloc(data_length);
					if (!pkey[found].big)
					{
						fprintf(stderr, "ERROR: Could not allocate memory.\n");
						error = 1;
						break;
					}
					memcpy(pkey[found].big, data, data_length);
					pkey[found].size = data_length;
				}
				break;
			// Do not need these
			case TAG_CREATED:
			case TAG_PUBLISH:
			case TAG_ACTIVATE:
			default:
				break;
		}
	}

	fclose(file_pointer);

	// Something went wrong. Clean up and quit.
	if (error)
	{
		free_key_material(pkey);
		return error;
	}

	// Create and set file permissions if the file does not exist.
	int fd = open(out_path, O_CREAT, S_IRUSR | S_IWUSR);
	if (fd == -1)
	{
		fprintf(stderr, "ERROR: Could not open the output file: %s (errno %i)\n",
			out_path, errno);
		free_key_material(pkey);
		return 1;
	}
	::close(fd);

	crypto_init();

	// Save the the key to the disk
	switch (algorithm)
	{
		case DNS_KEYALG_ERROR:
			fprintf(stderr, "ERROR: The algorithm %i was not given in the file.\n",
					algorithm);
			error = 1;
			break;
		case DNS_KEYALG_RSAMD5:
		case DNS_KEYALG_RSASHA1:
		case DNS_KEYALG_RSASHA1_NSEC3_SHA1:
		case DNS_KEYALG_RSASHA256:
		case DNS_KEYALG_RSASHA512:
			error = save_rsa_pkcs8(out_path, file_pin, pkey);
			break;
		case DNS_KEYALG_DSA:
		case DNS_KEYALG_DSA_NSEC3_SHA1:
			error = save_dsa_pkcs8(out_path, file_pin, pkey);
			break;
		case DNS_KEYALG_ECC:
		case DNS_KEYALG_ECC_GOST:
		default:
			fprintf(stderr, "ERROR: The algorithm %i is not supported.\n",
					algorithm);
			error = 1;
			break;
	}

	crypto_final();
	free_key_material(pkey);

	return error;
}

// Free allocated memory
void free_key_material(key_material_t* pkey)
{
	int i;

	if (!pkey)
	{
		return;
	}

	for (i = 0; i < TAG_MAX; i++)
	{
		if (pkey[i].big)
		{
			free(pkey[i].big);
		}
	}
}
