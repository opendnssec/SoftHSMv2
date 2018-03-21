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

/*****************************************************************************
 softhsm2-migrate.h

 This program can be used for migrating SoftHSM v1 databases to any
 PKCS#11 library. The default library is the libsofthsm2.so
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SOFTHSM2_MIGRATE_H
#define _SOFTHSM_V2_SOFTHSM2_MIGRATE_H

#include "cryptoki.h"
#include <sqlite3.h>

// Main functions

void usage();
int migrate(char* dbPath, CK_SLOT_ID slotID, char* userPIN, int noPublicKey);

// Support functions

sqlite3* openDB(char* dbPath);
int openP11(CK_SLOT_ID slotID, char* userPIN, CK_SESSION_HANDLE* hSession);
int db2session(sqlite3* db, CK_SESSION_HANDLE hSession, int noPublicKey);
int dbRSAPub2session(sqlite3* db, CK_OBJECT_HANDLE objectID, CK_SESSION_HANDLE hSession);
int dbRSAPriv2session(sqlite3* db, CK_OBJECT_HANDLE objectID, CK_SESSION_HANDLE hSession);
void freeTemplate(CK_ATTRIBUTE* attTemplate, int startIndex, int size);

// Database functions

CK_OBJECT_HANDLE* getObjects(sqlite3* db, CK_ULONG* objectCount);
CK_OBJECT_CLASS getObjectClass(CK_OBJECT_HANDLE objectRef);
CK_KEY_TYPE getKeyType(CK_OBJECT_HANDLE objectRef);
int getAttribute(CK_OBJECT_HANDLE objectRef, CK_ATTRIBUTE* attTemplate);
int prepStatements(sqlite3* db);
void finalStatements();

// Library

static void* moduleHandle;
extern CK_FUNCTION_LIST_PTR p11;

#endif // !_SOFTHSM_V2_SOFTHSM2_MIGRATE_H
