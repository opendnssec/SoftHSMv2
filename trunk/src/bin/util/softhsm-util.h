/* $Id$ */

/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation).
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

/*****************************************************************************
 softhsm-util.h

 This program can be used for interacting with HSMs using PKCS#11.
 The default library is the libsofthsm.so
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SOFTHSM_UTIL_H
#define _SOFTHSM_V2_SOFTHSM_UTIL_H

#include "pkcs11.h"

// Main functions

void usage();
int initToken(char *slot, char *label, char *soPIN, char *userPIN);
int showSlots();
int importKeyPair(char *filePath, char *filePIN, char *slot, char *userPIN, char *objectLabel, char *objectID, int forceExec, int noPublicKey);
int crypto_import_key_pair(CK_SESSION_HANDLE hSession, char *filePath, char *filePIN, char *label, char *objID, int objIDLen, int noPublicKey);

// Support functions

void crypto_init();
void crypto_final();

/// Hex
char* hexStrToBin(char *objectID, int idLength, int *newLen);
int hexdigit_to_int(char ch);

/// Library
static void *moduleHandle;
extern CK_FUNCTION_LIST_PTR p11;

/// PKCS#11 support
CK_OBJECT_HANDLE searchObject(CK_SESSION_HANDLE hSession, char *objID, int objIDLen);

#endif // !_SOFTHSM_V2_SOFTHSM_UTIL_H
