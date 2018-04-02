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
 softhsm2-migrate.cpp

 This program can be used for migrating SoftHSM v1 databases to any
 PKCS#11 library. The default library is the libsofthsm2.so
 *****************************************************************************/

#include <config.h>
#include "softhsm2-migrate.h"
#include "findslot.h"
#include "getpw.h"
#include "library.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include <iostream>
#include <fstream>
#include <sched.h>

#ifdef _WIN32
#define sched_yield() SleepEx(0, 0)
#endif

// Display the usage
void usage()
{
	printf("SoftHSM migration tool. From SoftHSM v1 database to PKCS#11.\n");
	printf("Usage: softhsm2-migrate [OPTIONS]\n");
	printf("Options:\n");
	printf("  -h                Shows this help screen.\n");
	printf("  --help            Shows this help screen.\n");
	printf("  --db <path>       The SoftHSM v1 database that is going to be migrated.\n");
	printf("  --module <path>   Use another PKCS#11 library than SoftHSM.\n");
	printf("  --no-public-key   Do not migrate the public key.\n");
	printf("  --pin <PIN>       The PIN for the normal user.\n");
	printf("  --serial <number> Will use the token with a matching serial number.\n");
	printf("  --slot <number>   The slot where the token is located.\n");
	printf("  --token <label>   Will use the token with a matching token label.\n");
	printf("  -v                Show version info.\n");
	printf("  --version         Show version info.\n");
}

// Enumeration of the long options
enum {
	OPT_HELP = 0x100,
	OPT_DB,
	OPT_MODULE,
	OPT_NO_PUBLIC_KEY,
	OPT_PIN,
	OPT_SERIAL,
	OPT_SLOT,
	OPT_TOKEN,
	OPT_VERSION
};

// Text representation of the long options
static const struct option long_options[] = {
	{ "help",            0, NULL, OPT_HELP },
	{ "db",              1, NULL, OPT_DB },
	{ "module",          1, NULL, OPT_MODULE },
	{ "no-public-key",   0, NULL, OPT_NO_PUBLIC_KEY },
	{ "pin",             1, NULL, OPT_PIN },
	{ "serial",          1, NULL, OPT_SERIAL },
	{ "slot",            1, NULL, OPT_SLOT },
	{ "token" ,          1, NULL, OPT_TOKEN },
	{ "version",         0, NULL, OPT_VERSION },
	{ NULL,              0, NULL, 0 }
};

CK_FUNCTION_LIST_PTR p11;

// Prepared statements
sqlite3_stmt* select_an_attribute_sql = NULL;
sqlite3_stmt* select_object_ids_sql = NULL;
sqlite3_stmt* count_object_id_sql = NULL;


// The main function
int main(int argc, char* argv[])
{
	int option_index = 0;
	int opt;

	char* dbPath = NULL;
	char* userPIN = NULL;
	char* module = NULL;
	char* slot = NULL;
	char* serial = NULL;
	char* token = NULL;
	char *errMsg = NULL;
	int noPublicKey = 0;

	int result = 0;
	CK_RV rv;

	moduleHandle = NULL;
	p11 = NULL;
	CK_SLOT_ID slotID = 0;

	if (argc == 1)
	{
		usage();
		exit(0);
	}

	while ((opt = getopt_long(argc, argv, "hv", long_options, &option_index)) != -1)
	{
		switch (opt)
		{
			case OPT_DB:
				dbPath = optarg;
				break;
			case OPT_SLOT:
				slot = optarg;
				break;
			case OPT_SERIAL:
				serial = optarg;
				break;
			case OPT_TOKEN:
				token = optarg;
				break;
			case OPT_MODULE:
				module = optarg;
				break;
			case OPT_NO_PUBLIC_KEY:
				noPublicKey = 1;
				break;
			case OPT_PIN:
				userPIN = optarg;
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

	// Get a pointer to the function list for PKCS#11 library
	CK_C_GetFunctionList pGetFunctionList = loadLibrary(module, &moduleHandle, &errMsg);
	if (pGetFunctionList == NULL)
	{
		fprintf(stderr, "ERROR: Could not load the PKCS#11 library/module: %s\n", errMsg);
		fprintf(stderr, "ERROR: Please check log files for additional information.\n");
		exit(1);
	}

	// Load the function list
	(*pGetFunctionList)(&p11);

	// Initialize the library
	rv = p11->C_Initialize(NULL_PTR);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not initialize the PKCS#11 library/module: %s\n", module ? module : DEFAULT_PKCS11_LIB);
		fprintf(stderr, "ERROR: Please check log files for additional information.\n");
		exit(1);
	}

	// Get the slotID
	result = findSlot(slot, serial, token, slotID);

	if (!result)
	{
		// Migrate the database
		result = migrate(dbPath, slotID, userPIN, noPublicKey);
	}

	// Finalize the library
	p11->C_Finalize(NULL_PTR);
	unloadLibrary(moduleHandle);

	return result;
}

// Migrate the database
int migrate(char* dbPath, CK_SLOT_ID slotID, char* userPIN, int noPublicKey)
{
	CK_SESSION_HANDLE hSession;
	sqlite3* db = NULL;
	int result;

	if (dbPath == NULL)
	{
		fprintf(stderr, "ERROR: A path to the database must be supplied. "
				"Use --db <path>\n");
		return 1;
	}

	// Open the database
	db = openDB(dbPath);
	if (db == NULL)
	{
		return 1;
	}

	// Connect to the PKCS#11 library
	result = openP11(slotID, userPIN, &hSession);
	if (result)
	{
		sqlite3_close(db);
		return result;
	}

	// Prepare the statements
	if (prepStatements(db))
	{
		fprintf(stderr, "ERROR: Could not prepare the statements\n");
		finalStatements();
		sqlite3_close(db);
		return 1;
	}

	// Start the migration
	result = db2session(db, hSession, noPublicKey);

	// Finalize the statements
	finalStatements();

	sqlite3_close(db);

	if (result)
	{
		fprintf(stderr, "ERROR: Unable to migrate all of the objects.\n");
	}
	else
	{
		printf("The database has been migrated to the new HSM\n");
	}

	return result;
}

// Prepare the statements
int prepStatements(sqlite3* db)
{
	select_an_attribute_sql = NULL;
	select_object_ids_sql = NULL;
	count_object_id_sql = NULL;

	const char select_an_attribute_str[] =	"SELECT value,length FROM Attributes WHERE objectID = ? AND type = ?;";
	const char select_object_ids_str[] =	"SELECT objectID FROM Objects;";
	const char count_object_id_str[] =	"SELECT COUNT(objectID) FROM Objects;";

	if
	(
		sqlite3_prepare_v2(db, select_an_attribute_str, -1, &select_an_attribute_sql, NULL) ||
		sqlite3_prepare_v2(db, select_object_ids_str, -1, &select_object_ids_sql, NULL) ||
		sqlite3_prepare_v2(db, count_object_id_str, -1, &count_object_id_sql, NULL)
	)
	{
		return 1;
	}

	return 0;
}

// Finalize the statements
void finalStatements()
{
	if (select_an_attribute_sql) sqlite3_finalize(select_an_attribute_sql);
	if (select_object_ids_sql) sqlite3_finalize(select_object_ids_sql);
	if (count_object_id_sql) sqlite3_finalize(count_object_id_sql);
}

// Open a connection to a valid SoftHSM v1 database
sqlite3* openDB(char* dbPath)
{
	int result;
	sqlite3* db = NULL;
	sqlite3_stmt* pragStatem = NULL;
	int dbVersion;

	// Open the database
	result = sqlite3_open(dbPath, &db);
	if (result)
	{
		fprintf(stderr, "ERROR: Could not open token database. "
				"Probably wrong path or privileges: %s\n", dbPath);
		return NULL;
	}

	// Check the schema version
	if (sqlite3_prepare_v2(db, "PRAGMA user_version;", -1, &pragStatem, NULL))
	{
		fprintf(stderr, "ERROR: Could not prepare a SQL statement\n");
		sqlite3_close(db);
		return NULL;
	}
	if (sqlite3_step(pragStatem) == SQLITE_ROW)
	{
		dbVersion = sqlite3_column_int(pragStatem, 0);
		sqlite3_finalize(pragStatem);

		if (dbVersion != 100)
		{
			fprintf(stderr, "ERROR: Wrong database schema version: %s\n", dbPath);
			sqlite3_close(db);
			return NULL;
		}
	}
	else
	{
		fprintf(stderr, "ERROR: The token database has not been initialized by SoftHSM\n");
		sqlite3_finalize(pragStatem);
		sqlite3_close(db);
		return NULL;
	}

	// Check that the Token table exist
	result = sqlite3_exec(db, "SELECT COUNT(variableID) FROM Token;", NULL, NULL, NULL);
	if (result)
	{
		fprintf(stderr, "ERROR: The Token table is missing the in database\n");
		sqlite3_close(db);
		return NULL;
	}

	// Check that the Objects table exist
	result = sqlite3_exec(db, "SELECT COUNT(objectID) FROM Objects;", NULL, NULL, NULL);
	if (result)
	{
		fprintf(stderr, "ERROR: The Objects table is missing the in database\n");
		sqlite3_close(db);
		return NULL;
	}

	// Check that the Attributes table exist
	result = sqlite3_exec(db, "SELECT COUNT(attributeID) FROM Attributes;", NULL, NULL, NULL);
	if (result)
	{
		fprintf(stderr, "ERROR: The Attributes table is missing in the database\n");
		sqlite3_close(db);
		return NULL;
	}

	return db;
}

// Connect and login to the token
int openP11(CK_SLOT_ID slotID, char* userPIN, CK_SESSION_HANDLE* hSession)
{
	char user_pin_copy[MAX_PIN_LEN+1];
	CK_RV rv;

	rv = p11->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION,
					NULL_PTR, NULL_PTR, hSession);
	if (rv != CKR_OK)
	{
		if (rv == CKR_SLOT_ID_INVALID)
		{
			fprintf(stderr, "ERROR: The given slot does not exist.\n");
		}
		else
		{
			fprintf(stderr, "ERROR: Could not open a session on the given slot.\n");
		}
		return 1;
	}

	// Get the password
	if (getPW(userPIN, user_pin_copy, CKU_USER) != 0)
	{
		fprintf(stderr, "ERROR: Could not get user PIN\n");
		return 1;
	}

	rv = p11->C_Login(*hSession, CKU_USER, (CK_UTF8CHAR_PTR)user_pin_copy, strlen(user_pin_copy));
	if (rv != CKR_OK)
	{
		if (rv == CKR_PIN_INCORRECT) {
			fprintf(stderr, "ERROR: The given user PIN does not match the one in the token.\n");
		}
		else
		{
			fprintf(stderr, "ERROR: Could not log in on the token.\n");
		}
		return 1;
	}

	return 0;
}

// Migrate the database to the session
int db2session(sqlite3* db, CK_SESSION_HANDLE hSession, int noPublicKey)
{
	CK_ULONG objectCount;
	int result = 0, rv;
	CK_OBJECT_HANDLE* objects = NULL;
	CK_OBJECT_CLASS ckClass;

	// Get all objects
	objects = getObjects(db, &objectCount);
	if (objects == NULL)
	{
		fprintf(stderr, "ERROR: Could not find any objects in the database.\n");
		return 1;
	}

	// Loop over all objects
	for (unsigned i = 0; i < objectCount; i++)
	{
		ckClass = getObjectClass(objects[i]);

		switch (ckClass)
		{
			case CKO_PUBLIC_KEY:
				if (noPublicKey) continue;
				if (getKeyType(objects[i]) != CKK_RSA)
				{
					fprintf(stderr, "ERROR: Cannot export object %lu. Only supporting RSA keys. "
						"Continuing.\n", objects[i]);
					result = 1;
					break;
				}
				rv = dbRSAPub2session(db, objects[i], hSession);
				if (rv) result = 1;
				break;
			case CKO_PRIVATE_KEY:
				if (getKeyType(objects[i]) != CKK_RSA)
				{
					fprintf(stderr, "ERROR: Cannot export object %lu. Only supporting RSA keys. "
						"Continuing.\n", objects[i]);
					result = 1;
					break;
				}
				rv = dbRSAPriv2session(db, objects[i], hSession);
				if (rv) result = 1;
				break;
			case CKO_VENDOR_DEFINED:
				fprintf(stderr, "ERROR: Could not get the class of object %lu. "
						"Continuing.\n", objects[i]);
				result = 1;
				break;
			default:
				fprintf(stderr, "ERROR: Not supporting class %lu in object %lu. "
						"Continuing.\n", ckClass, objects[i]);
				result = 1;
				break;
		}
	}

	free(objects);

	return result;
}

// Get the key type from key objects
CK_KEY_TYPE getKeyType(CK_OBJECT_HANDLE objectRef)
{
	int retSQL = 0;
	CK_KEY_TYPE retVal = CKK_VENDOR_DEFINED;

	sqlite3_bind_int(select_an_attribute_sql, 1, objectRef);
	sqlite3_bind_int(select_an_attribute_sql, 2, CKA_KEY_TYPE);

	// Get result
	while ((retSQL = sqlite3_step(select_an_attribute_sql)) == SQLITE_BUSY)
	{
		sched_yield();
	}

	// Get attribute
	if (retSQL == SQLITE_ROW)
	{
		CK_VOID_PTR pValue = (CK_VOID_PTR)sqlite3_column_blob(select_an_attribute_sql, 0);
		CK_ULONG length = sqlite3_column_int(select_an_attribute_sql, 1);

		if (pValue != NULL_PTR)
		{
			// 32/64-bit DB on 32/64-bit system
			if (length == sizeof(CK_KEY_TYPE))
			{
				retVal = *(CK_KEY_TYPE*)pValue;
			}
			// 32-bit DB on 64-bit system (LP64)
			else if (length == sizeof(unsigned int))
			{
				retVal = *(unsigned int*)pValue;
			}
		}
	}

	sqlite3_reset(select_an_attribute_sql);

	return retVal;
}

// Get the class of the object
CK_OBJECT_CLASS getObjectClass(CK_OBJECT_HANDLE objectRef)
{
	int retSQL = 0;
	CK_OBJECT_CLASS retVal = CKO_VENDOR_DEFINED;

	sqlite3_bind_int(select_an_attribute_sql, 1, objectRef);
	sqlite3_bind_int(select_an_attribute_sql, 2, CKA_CLASS);

	// Get the result
	while ((retSQL = sqlite3_step(select_an_attribute_sql)) == SQLITE_BUSY)
	{
		sched_yield();
	}

	// Get attribute
	if (retSQL == SQLITE_ROW)
	{
		CK_VOID_PTR pValue = (CK_VOID_PTR)sqlite3_column_blob(select_an_attribute_sql, 0);
		CK_ULONG length = sqlite3_column_int(select_an_attribute_sql, 1);

		if (pValue != NULL_PTR)
		{
			// 32/64-bit DB on 32/64-bit system
			if (length == sizeof(CK_OBJECT_CLASS))
			{
				retVal = *(CK_OBJECT_CLASS*)pValue;
			}
			// 32-bit DB on 64-bit system (LP64)
			else if (length == sizeof(unsigned int))
			{
				retVal = *(unsigned int*)pValue;
			}
		}
	}

	sqlite3_reset(select_an_attribute_sql);

	return retVal;
}

// Get all object IDs
CK_OBJECT_HANDLE* getObjects(sqlite3* /*db*/, CK_ULONG* objectCount)
{
	CK_ULONG objectsInDB;
	CK_ULONG counter = 0;
	CK_OBJECT_HANDLE* objectRefs = NULL;
	int retSQL = 0;

	*objectCount = 0;

	// Find out how many objects we have.
	while ((retSQL = sqlite3_step(count_object_id_sql)) == SQLITE_BUSY)
	{
		sched_yield();
	}

	if (retSQL != SQLITE_ROW)
	{
		fprintf(stderr, "ERROR: Could not count the number of objects in the database\n");
		sqlite3_reset(count_object_id_sql);
		return NULL;
	}

	// Get the number of objects
	objectsInDB = sqlite3_column_int(count_object_id_sql, 0);
	sqlite3_reset(count_object_id_sql);

	if (!objectsInDB)
	{
		fprintf(stderr, "ERROR: There are not objects in the database\n");
		return NULL;
	}

	// Create the object-reference buffer
	objectRefs = (CK_OBJECT_HANDLE*)malloc(objectsInDB * sizeof(CK_OBJECT_HANDLE));
	if (objectRefs == NULL)
	{
		fprintf(stderr, "ERROR: Could not allocate memory\n");
		return NULL;
	}

	// Get all the object ids
	while
	(
		((retSQL = sqlite3_step(select_object_ids_sql)) == SQLITE_BUSY || retSQL == SQLITE_ROW) &&
		counter < objectsInDB
	)
	{
		if(retSQL == SQLITE_BUSY)
		{
			sched_yield();
			continue;
		}

		objectRefs[counter++] = sqlite3_column_int(select_object_ids_sql, 0);
	}

	*objectCount = counter;

	sqlite3_reset(select_object_ids_sql);

	return objectRefs;
}

// Extract the information about the public RSA key and save it in the token
int dbRSAPub2session(sqlite3* /*db*/, CK_OBJECT_HANDLE objectID, CK_SESSION_HANDLE hSession)
{
	int result = 0;
	int i;
	CK_OBJECT_HANDLE hKey;
	CK_RV rv;
	CK_OBJECT_CLASS ckClass = CKO_PUBLIC_KEY;
	CK_KEY_TYPE ckType = CKK_RSA;

	// All required CK_ULONG attributes have known/fixed values.
	// So no need read them from the DB and no need to handle
	// convertion from 32-bit to 64-bit.
	CK_ATTRIBUTE pubTemplate[] = {
		{ CKA_CLASS,		&ckClass, sizeof(ckClass) },
		{ CKA_KEY_TYPE,		&ckType, sizeof(ckType) },
		{ CKA_TOKEN,		NULL,	0 },
		{ CKA_PRIVATE,		NULL,	0 },
		{ CKA_MODIFIABLE,	NULL,	0 },
		{ CKA_LABEL,		NULL,	0 },
		{ CKA_ID,		NULL,	0 },
		{ CKA_START_DATE,	NULL,	0 },
		{ CKA_END_DATE,		NULL,	0 },
		{ CKA_DERIVE,		NULL,	0 },
		{ CKA_SUBJECT,		NULL,	0 },
		{ CKA_ENCRYPT,		NULL,	0 },
		{ CKA_VERIFY,		NULL,	0 },
		{ CKA_VERIFY_RECOVER,	NULL,	0 },
		{ CKA_WRAP,		NULL,	0 },
		{ CKA_MODULUS,		NULL,	0 },
		{ CKA_PUBLIC_EXPONENT,	NULL,	0 }
	};

	for (i = 2; i < 17; i++)
	{
		result = getAttribute(objectID, &pubTemplate[i]);
		if (result)
		{
			freeTemplate(pubTemplate, 2, 17);
			return 1;
		}
	}

	rv = p11->C_CreateObject(hSession, pubTemplate, 17, &hKey);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR %X: Could not save the public key in the token. "
				"Skipping object %lu\n", (unsigned int)rv, objectID);
		result = 1;
	}
	else
	{
		printf("Object %lu has been migrated\n", objectID);
	}

	freeTemplate(pubTemplate, 2, 17);

	return result;
}

// Extract the information about the private RSA key and save it in the token
int dbRSAPriv2session(sqlite3* /*db*/, CK_OBJECT_HANDLE objectID, CK_SESSION_HANDLE hSession)
{
	int result = 0;
	int i;
	CK_OBJECT_HANDLE hKey;
	CK_RV rv;
	CK_OBJECT_CLASS ckClass = CKO_PRIVATE_KEY;

	// All required CK_ULONG attributes have known/fixed values.
	// So no need read them from the DB and no need to handle
	// convertion from 32-bit to 64-bit.
	CK_ATTRIBUTE privTemplate[] = {
		{ CKA_CLASS,			&ckClass, sizeof(ckClass) },
		{ CKA_TOKEN,			NULL,	0 },
		{ CKA_PRIVATE,			NULL,	0 },
		{ CKA_MODIFIABLE,		NULL,	0 },
		{ CKA_LABEL,			NULL,	0 },
		{ CKA_KEY_TYPE,			NULL,	0 },
		{ CKA_ID,			NULL,	0 },
		{ CKA_START_DATE,		NULL,	0 },
		{ CKA_END_DATE,			NULL,	0 },
		{ CKA_DERIVE,			NULL,	0 },
		{ CKA_SUBJECT,			NULL,	0 },
		{ CKA_SENSITIVE,		NULL,	0 },
		{ CKA_DECRYPT,			NULL,	0 },
		{ CKA_SIGN,			NULL,	0 },
		{ CKA_SIGN_RECOVER,		NULL,	0 },
		{ CKA_UNWRAP,			NULL,	0 },
		{ CKA_EXTRACTABLE,		NULL,	0 },
		{ CKA_WRAP_WITH_TRUSTED,	NULL,	0 },
		{ CKA_MODULUS,			NULL,	0 },
		{ CKA_PUBLIC_EXPONENT,		NULL,	0 },
		{ CKA_PRIVATE_EXPONENT,		NULL,	0 },
		{ CKA_PRIME_1,			NULL,	0 },
		{ CKA_PRIME_2,			NULL,	0 }
// SoftHSM v1 did not store these values
//		{ CKA_EXPONENT_1,		NULL,	0 },
//		{ CKA_EXPONENT_2,		NULL,	0 },
//		{ CKA_COEFFICIENT,		NULL,	0 }
	};

	for (i = 1; i < 23; i++)
	{
		result = getAttribute(objectID, &privTemplate[i]);
		if (result)
		{
			freeTemplate(privTemplate, 1, 23);
			return 1;
		}
	}

	rv = p11->C_CreateObject(hSession, privTemplate, 23, &hKey);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR %X: Could not save the private key in the token. "
				"Skipping object %lu\n", (unsigned int)rv, objectID);
		result = 1;
	}
	else
	{
		printf("Object %lu has been migrated\n", objectID);
	}

	freeTemplate(privTemplate, 1, 23);

	return result;
}

// Get the value of the given attribute
int getAttribute(CK_OBJECT_HANDLE objectRef, CK_ATTRIBUTE* attTemplate)
{
	int retSQL = 0;
	int retVal = 0;

	sqlite3_bind_int(select_an_attribute_sql, 1, objectRef);
	sqlite3_bind_int(select_an_attribute_sql, 2, attTemplate->type);

	// Get result
	while ((retSQL = sqlite3_step(select_an_attribute_sql)) == SQLITE_BUSY)
	{
		sched_yield();
	}

	// Get the attribute
	if (retSQL == SQLITE_ROW)
	{
		CK_VOID_PTR pValue = (CK_VOID_PTR)sqlite3_column_blob(select_an_attribute_sql, 0);
		CK_ULONG length = sqlite3_column_int(select_an_attribute_sql, 1);

		if (length)
		{
			attTemplate->pValue = malloc(length);
			if (!attTemplate->pValue)
			{
				fprintf(stderr, "ERROR: Could not allocate memory. "
						"Skipping object %lu\n", objectRef);
				retVal = 1;
			}
			else
			{
				// Copy data
				memcpy(attTemplate->pValue, pValue, length);
			}
		}

		attTemplate->ulValueLen = length;
	}
	else
	{
		fprintf(stderr, "ERROR: Do not have attribute %lu. "
				"Skipping object %lu\n", attTemplate->type, objectRef);
		retVal = 1;
	}

	sqlite3_reset(select_an_attribute_sql);

	return retVal;
}

// Free allocated memory in the template
void freeTemplate(CK_ATTRIBUTE* attTemplate, int startIndex, int size)
{
	int i;

	if (!attTemplate) return;

	for (i = startIndex; i < size; i++)
	{
		if(attTemplate[i].pValue)
		{
			free(attTemplate[i].pValue);
		}
	}
}
