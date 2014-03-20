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

#ifndef _SOFTHSM_V2_SOFTHSM2_KEYCONV_H
#define _SOFTHSM_V2_SOFTHSM2_KEYCONV_H 1

#include <stdlib.h>

typedef struct key_material_t {
	unsigned long size;
	void* big;
	key_material_t() {
		size = 0;
		big = NULL;
	}
} key_material_t;

// Main functions

void usage();
int to_pkcs8(char* in_path, char* out_path, char* file_pin);

// Support functions

int save_rsa_pkcs8(char* out_path, char* file_pin, key_material_t* pkey);
int save_dsa_pkcs8(char* out_path, char* file_pin, key_material_t* pkey);
void free_key_material(key_material_t* pkey);
void crypto_init();
void crypto_final();

// base64.c prototypes

#ifdef __cplusplus
extern "C" {
#endif
int b64_pton(const char* , unsigned char*, size_t);
int b64_ntop(const unsigned char*, size_t, char*, size_t);
#ifdef __cplusplus
}
#endif

// The BIND file version number.
#define FILE_MAJOR_VERSION	1
#define FILE_MINOR_VERSION	3

// Key algorithm number
#define DNS_KEYALG_ERROR		-1
#define DNS_KEYALG_RSAMD5		1
#define DNS_KEYALG_DSA			3
#define DNS_KEYALG_ECC			4
#define DNS_KEYALG_RSASHA1		5
#define DNS_KEYALG_DSA_NSEC3_SHA1	6
#define DNS_KEYALG_RSASHA1_NSEC3_SHA1	7
#define DNS_KEYALG_RSASHA256		8
#define DNS_KEYALG_RSASHA512		10
#define DNS_KEYALG_ECC_GOST		12

// Maximum number of lines / line length
#define MAX_LINE 4096

// The text fields supported
#if !defined(KEYCONV_BOTAN) && !defined(KEYCONV_OSSL)
static const char* file_tags[] = {
	"Private-key-format:",
	"Algorithm:",
	"Modulus:",
	"PublicExponent:",
	"PrivateExponent:",
	"Prime1:",
	"Prime2:",
	"Exponent1:",
	"Exponent2:",
	"Coefficient:",
	"Prime(p):",
	"Private_value(x):",
	"Public_value(y):",
	"Subprime(q):",
	"Base(g):",
	"Created:",
	"Publish:",
	"Activate:",
	NULL
};
#endif

// The number of each text field.
// Must match the tags above.
enum FILE_TAGS {
	TAG_VERSION = 0,
	TAG_ALGORITHM,
	TAG_MODULUS,
	TAG_PUBEXP,
	TAG_PRIVEXP,
	TAG_PRIME1,
	TAG_PRIME2,
	TAG_EXP1,
	TAG_EXP2,
	TAG_COEFF,
	TAG_PRIME,
	TAG_PRIVVAL,
	TAG_PUBVAL,
	TAG_SUBPRIME,
	TAG_BASE,
	TAG_CREATED,
	TAG_PUBLISH,
	TAG_ACTIVATE,
	// So we know how long this list is
	TAG_MAX
};

#endif /* _SOFTHSM_V2_SOFTHSM2_KEYCONV_H */
