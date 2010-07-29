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
 softhsm-util.cpp

 This program can be used for interacting with HSMs using PKCS#11.
 The default library is the libsofthsm.so
 *****************************************************************************/

#include <config.h>
#include "softhsm-util.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#if defined(HAVE_DLOPEN)
#include <dlfcn.h>
#endif

// Display the usage
void usage()
{
	printf("Support tool for PKCS#11\n");
	printf("Usage: softhsm-util [ACTION] [OPTIONS]\n");
	printf("Action:\n");
	printf("  -h                Shows this help screen.\n");
	printf("  --help            Shows this help screen.\n");
	printf("  --import <path>   Import a key pair from the given path.\n");
	printf("                    The file must be in PKCS#8-format.\n");
	printf("                    Use with --file-pin, --slot, --label, --id,\n");
	printf("                    --no-public-key, and --pin.\n");
	printf("  --init-token      Initialize the token at a given slot.\n");
	printf("                    Use with --slot, --label, --so-pin, and --pin.\n");
	printf("                    WARNING: Any content in token token will be erased.\n");
	printf("  --show-slots      Display all the available slots.\n");
	printf("  -v                Show version info.\n");
	printf("  --version         Show version info.\n");
	printf("Options:\n");
	printf("  --file-pin <PIN>  Supply a PIN if the file is encrypted.\n");
	printf("  --force           Used to override a warning.\n");
	printf("  --id <hex>        Defines the ID of the object. Hexadecimal characters.\n");
	printf("                    Use with --force if multiple key pairs may share\n");
	printf("                    the same ID.\n");
	printf("  --label <text>    Defines the label of the object or the token.\n");
	printf("  --module <path>   Use another PKCS#11 library than SoftHSM.\n");
	printf("  --no-public-key   Do not import the public key.\n");
	printf("  --pin <PIN>       The PIN for the normal user.\n");
	printf("  --slot <number>   The slot where the token is located.\n");
	printf("  --so-pin <PIN>    The PIN for the Security Officer (SO).\n");
}

// Enumeration of the long options
enum {
	OPT_FILE_PIN = 0x100,
	OPT_FORCE,
	OPT_HELP,
	OPT_ID,
	OPT_IMPORT,
	OPT_INIT_TOKEN,
	OPT_LABEL,
	OPT_MODULE,
	OPT_NO_PUBLIC_KEY,
	OPT_PIN,
	OPT_SHOW_SLOTS,
	OPT_SLOT,
	OPT_SO_PIN,
	OPT_VERSION
};

// Text representation of the long options
static const struct option long_options[] = {
	{ "file-pin",        1, NULL, OPT_FILE_PIN },
	{ "force",           0, NULL, OPT_FORCE },
	{ "help",            0, NULL, OPT_HELP },
	{ "id",              1, NULL, OPT_ID },
	{ "import",          1, NULL, OPT_IMPORT },
	{ "init-token",      0, NULL, OPT_INIT_TOKEN },
	{ "label",           1, NULL, OPT_LABEL },
	{ "module",          1, NULL, OPT_MODULE },
	{ "no-public-key",   0, NULL, OPT_NO_PUBLIC_KEY },
	{ "pin",             1, NULL, OPT_PIN },
	{ "show-slots",      0, NULL, OPT_SHOW_SLOTS },
	{ "slot",            1, NULL, OPT_SLOT },
	{ "so-pin",          1, NULL, OPT_SO_PIN },
	{ "version",         0, NULL, OPT_VERSION },
	{ NULL,              0, NULL, 0 }
};

CK_FUNCTION_LIST_PTR p11;

// The main function
int main(int argc, char *argv[])
{
	int option_index = 0;
	int opt;

	char *inPath = NULL;
	char *outPath = NULL;
	char *soPIN = NULL;
	char *userPIN = NULL;
	char *filePIN = NULL;
	char *label = NULL;
	char *module = NULL;
	char *objectID = NULL;
	char *slot = NULL;
	int forceExec = 0;
	int noPublicKey = 0;

	int doInitToken = 0;
	int doShowSlots = 0;
	int doImport = 0;
	int doExport = 0;
	int action = 0;
	int rv = 0;

	moduleHandle = NULL;
	p11 = NULL;

	while ((opt = getopt_long(argc, argv, "hv", long_options, &option_index)) != -1)
	{
		switch (opt)
		{
			case OPT_SHOW_SLOTS:
				doShowSlots = 1;
				action++;
				break;
			case OPT_INIT_TOKEN:
				doInitToken = 1;
				action++;
				break;
			case OPT_IMPORT:
				doImport = 1;
				action++;
				inPath = optarg;
				break;
			case OPT_SLOT:
				slot = optarg;
				break;
			case OPT_LABEL:
				label = optarg;
				break;
			case OPT_MODULE:
				module = optarg;
				break;
			case OPT_NO_PUBLIC_KEY:
				noPublicKey = 1;
				break;
			case OPT_ID:
				objectID = optarg;
				break;
			case OPT_SO_PIN:
				soPIN = optarg;
				break;
			case OPT_PIN:
				userPIN = optarg;
				break;
			case OPT_FILE_PIN:
				filePIN = optarg;
				break;
			case OPT_FORCE:
				forceExec = 1;
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

	// No action given, display the usage.
	if (action == 0)
	{
		usage();
	}
	else
	{
		// Get a pointer to the function list for PKCS#11 library
		CK_C_GetFunctionList pGetFunctionList = loadLibrary(module);
		if (pGetFunctionList == NULL)
		{
			fprintf(stderr, "ERROR: Could not load the library.\n");
			exit(1);
		}

		// Load the function list
		(*pGetFunctionList)(&p11);

		// Initialize the library
		CK_RV rv = p11->C_Initialize(NULL_PTR);
		if (rv != CKR_OK)
		{
			fprintf(stderr, "ERROR: Could not initialize the library.\n");
			exit(1);
		}
	}

	// We should create the token.
	if (doInitToken)
	{
		rv = initToken(slot, label, soPIN, userPIN);
	}

	// Show all available slots
	if (doShowSlots)
	{
		rv = showSlots();
	}

	// Import a key pair from the given path
	if (doImport)
	{
		rv = importKeyPair(inPath, filePIN, slot, userPIN, label, objectID, 
					forceExec, noPublicKey);
	}

	// Finalize the library
	if (action)
	{
		p11->C_Finalize(NULL_PTR);
		if (moduleHandle)
		{
#if defined(HAVE_LOADLIBRARY)
			// no idea
#elif defined(HAVE_DLOPEN)
			dlclose(moduleHandle);
#endif
		}
	}

	return rv;
}

// Load the PKCS#11 library
CK_C_GetFunctionList loadLibrary(char *module)
{
	CK_C_GetFunctionList pGetFunctionList = NULL;

#if defined(HAVE_LOADLIBRARY)
	// Load PKCS #11 library
	if (module)
	{
		HINSTANCE hDLL = LoadLibrary(_T(module));
	}
	else
	{
		HINSTANCE hDLL = LoadLibrary(_T(DEFAULT_PKCS11_LIB));
	}

	if (hDLL == NULL)
	{
		// Failed to load the PKCS #11 library
		return NULL;
	}

	// Retrieve the entry point for C_GetFunctionList
	pGetFunctionList = (CK_C_GetFunctionList) GetProcAddress(hDLL, _T("C_GetFunctionList"));
            
#elif defined(HAVE_DLOPEN)
	// Load PKCS #11 library
	void* pDynLib;
	if (module)
	{
		pDynLib = dlopen(module, RTLD_NOW | RTLD_LOCAL);
	}
	else
	{
		pDynLib = dlopen(DEFAULT_PKCS11_LIB, RTLD_NOW | RTLD_LOCAL);
	}

	if (pDynLib == NULL)
	{
		// Failed to load the PKCS #11 library
		return NULL;
	}

	// Retrieve the entry point for C_GetFunctionList
	pGetFunctionList = (CK_C_GetFunctionList) dlsym(pDynLib, "C_GetFunctionList");

	// Store the handle so we can dlclose it later
	moduleHandle = pDynLib;

#else
	fprintf(stderr, "ERROR: Not compiled with library support.\n");

	return NULL;
#endif

	return pGetFunctionList;
}

// Initialize the token
int initToken(char *slot, char *label, char *soPIN, char *userPIN)
{
	char so_pin_copy[MAX_PIN_LEN+1];
	char user_pin_copy[MAX_PIN_LEN+1];

	if (slot == NULL)
	{
		fprintf(stderr, "ERROR: A slot number must be supplied. "
				"Use --slot <number>\n");
		return 1;
	}

	if (label == NULL)
	{
		fprintf(stderr, "ERROR: A label for the token must be supplied. "
				"Use --label <text>\n");
		return 1;
	}

	if (strlen(label) > 32)
	{
		fprintf(stderr, "ERROR: The token label must not have a length "
				"greater than 32 chars.\n");
		return 1;
	}

	// Get the passwords
	getPW(soPIN, so_pin_copy, CKU_SO);
	getPW(userPIN, user_pin_copy, CKU_USER);

	// Load the variables
	CK_SLOT_ID slotID = atoi(slot);
	CK_UTF8CHAR paddedLabel[32];
	memset(paddedLabel, ' ', sizeof(paddedLabel));
	memcpy(paddedLabel, label, strlen(label));

	CK_RV rv = p11->C_InitToken(slotID, (CK_UTF8CHAR_PTR)so_pin_copy, strlen(so_pin_copy), paddedLabel);

	switch (rv)
	{
		case CKR_OK:
			break;
		case CKR_SLOT_ID_INVALID:
			fprintf(stderr, "CKR_SLOT_ID_INVALID: Slot %lu does not exist.\n", slotID);
			return 1;
			break;
		case CKR_PIN_INCORRECT:
			fprintf(stderr, "CKR_PIN_INCORRECT: The given SO PIN does not match the "
					"one in the token. Needed when reinitializing the token.\n");
			return 1;
			break;
		case CKR_TOKEN_NOT_PRESENT:
			fprintf(stderr, "CKR_TOKEN_NOT_PRESENT: The token is not present. "
					"Please read the HSM manual for further assistance.\n");
			return 1;
			break;
		default:
			fprintf(stderr, "ERROR %X: Could not initialize the token.\n", rv);
			return 1;
			break;
	}

	CK_SESSION_HANDLE hSession;
	rv = p11->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not open a session with the library.\n");
		return 1;
	}

	rv = p11->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR)so_pin_copy, strlen(so_pin_copy));
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not log in on the token.\n");
		return 1;
	}

	rv = p11->C_InitPIN(hSession, (CK_UTF8CHAR_PTR)user_pin_copy, strlen(user_pin_copy));
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not initialize the user PIN.\n");
		return 1;
	}

	printf("The token has been initialized.\n");

	return 0;
}

// Get a password from the user
void getPW(char *pin, char *newPIN, CK_ULONG userType)
{
	// Keep a copy of the PIN because getpass/getpassphrase 
	// will overwrite the previous PIN.
	char password[MAX_PIN_LEN+1];

	int length = 0;

	if (pin)
	{
		length = strlen(pin);
	}

	while (length < MIN_PIN_LEN || length > MAX_PIN_LEN)
	{
		if (userType == CKU_SO)
		{
			printf("*** SO PIN (%i-%i characters) ***\n",
				MIN_PIN_LEN, MAX_PIN_LEN); 
		}
		else
		{
			printf("*** User PIN (%i-%i characters) ***\n",
				MIN_PIN_LEN, MAX_PIN_LEN); 
		}

#ifdef HAVE_GETPASSPHRASE
		if (userType == CKU_SO)
		{
			pin = getpassphrase("Please enter SO PIN: ");
		}
		else
		{
			pin = getpassphrase("Please enter user PIN: ");
		}
#else
		if (userType == CKU_SO)
		{
			pin = getpass("Please enter SO PIN: ");
		}
		else
		{
			pin = getpass("Please enter user PIN: ");
		}
#endif

		length = strlen(pin);
		if (length < MIN_PIN_LEN || length > MAX_PIN_LEN)
		{
			fprintf(stderr, "ERROR: The length of the PIN is out of range.\n");
			length = 0;
			continue;
		}
		strcpy(password, pin);

#ifdef HAVE_GETPASSPHRASE
		if (userType == CKU_SO)
		{
			pin = getpassphrase("Please reenter SO PIN: ");
		}
		else
		{
			pin = getpassphrase("Please reenter user PIN: ");
		}
#else
		if (userType == CKU_SO)
		{
			pin = getpass("Please reenter SO PIN: ");
		}
		else
		{
			pin = getpass("Please reenter user PIN: ");
		}
#endif

		if (strcmp(password, pin))
		{
			fprintf(stderr, "ERROR: The entered PINs are not equal.\n");
			length = 0;
			continue;
		}
	}

	strcpy(newPIN, pin);
}

// Show what slots are available
int showSlots()
{
	CK_ULONG ulSlotCount;
	CK_RV rv = p11->C_GetSlotList(CK_FALSE, NULL_PTR, &ulSlotCount);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not get the number of slots.\n");
		return 1;
	}

	CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR) malloc(ulSlotCount*sizeof(CK_SLOT_ID));
	if (!pSlotList)
	{
		fprintf(stderr, "ERROR: Could not allocate memory.\n");
		return 1;
	}

	rv = p11->C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not get the slot list.\n");
		free(pSlotList);
		return 1;
	}

	printf("Available slots:\n");

	for (unsigned int i = 0; i < ulSlotCount; i++)
	{
		CK_SLOT_INFO slotInfo;
		CK_TOKEN_INFO tokenInfo;

		rv = p11->C_GetSlotInfo(pSlotList[i], &slotInfo);
		if (rv != CKR_OK)
		{  
			fprintf(stderr, "ERROR: Could not get info about slot %lu.\n", pSlotList[i]);
			continue;
		}

		printf("Slot %lu\n", pSlotList[i]);
		printf("    Slot info:\n");
		printf("        Description:      %.*s\n", 64, slotInfo.slotDescription);
		printf("        Manufacturer ID:  %.*s\n", 32, slotInfo.manufacturerID);
		printf("        Hardware version: %i.%i\n", slotInfo.hardwareVersion.major,
							    slotInfo.hardwareVersion.minor);
		printf("        Firmware version: %i.%i\n", slotInfo.firmwareVersion.major,
							    slotInfo.firmwareVersion.minor);
		printf("        Token present:    ");
		if ((slotInfo.flags & CKF_TOKEN_PRESENT) == 0)
		{
			printf("no\n");
			continue;
		}

		printf("yes\n");
		printf("    Token info:\n");

		rv = p11->C_GetTokenInfo(pSlotList[i], &tokenInfo);
		if (rv != CKR_OK)
		{
			fprintf(stderr, "ERROR: Could not get info about the token in slot %lu.\n", 
				pSlotList[i]);
			continue;
		}

		printf("        Manufacturer ID:  %.*s\n", 32, tokenInfo.manufacturerID);
		printf("        Model:            %.*s\n", 16, tokenInfo.model);
		printf("        Hardware version: %i.%i\n", tokenInfo.hardwareVersion.major,
							    tokenInfo.hardwareVersion.minor);
		printf("        Firmware version: %i.%i\n", tokenInfo.firmwareVersion.major,
							    tokenInfo.firmwareVersion.minor);
		printf("        Serial number:    %.*s\n", 16, tokenInfo.serialNumber);
		printf("        Initialized:      ");
		if ((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == 0)
		{
			printf("no\n");
		}
		else
		{
			printf("yes\n");
		}

		printf("        User PIN init.:   ");
		if ((tokenInfo.flags & CKF_USER_PIN_INITIALIZED) == 0)
		{
			printf("no\n");
		}
		else
		{
			printf("yes\n");
		}

		printf("        Label:            %.*s\n", 32, tokenInfo.label);

	}

	free(pSlotList);

	return 0;
}

// Import a key pair from given path
int importKeyPair
(
	char *filePath,
	char *filePIN,
	char *slot,
	char *userPIN,
	char *label,
	char *objectID,
	int forceExec,
	int noPublicKey
)
{
	char user_pin_copy[MAX_PIN_LEN+1];

	if (slot == NULL)
	{
		fprintf(stderr, "ERROR: A slot number must be supplied. "
				"Use --slot <number>\n");
		return 1;
	}

	if (label == NULL)
	{
		fprintf(stderr, "ERROR: A label for the object must be supplied. "
				"Use --label <text>\n");
		return 1;
	}

	if (objectID == NULL)
	{
		fprintf(stderr, "ERROR: An ID for the object must be supplied. "
				"Use --id <hex>\n");
		return 1;
	}

	int objIDLen = 0;
	char *objID = hexStrToBin(objectID, strlen(objectID), &objIDLen);
	if (objID == NULL)
	{
		fprintf(stderr, "Please edit --id <hex> to correct error.\n");
		return 1;
	}

	CK_SLOT_ID slotID = atoi(slot);
	CK_SESSION_HANDLE hSession;
	CK_RV rv = p11->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION,
					NULL_PTR, NULL_PTR, &hSession);
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
		free(objID);
		return 1;
	}

	// Get the password
	getPW(userPIN, user_pin_copy, CKU_USER);

	rv = p11->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)user_pin_copy, strlen(user_pin_copy));
	if (rv != CKR_OK)
	{
		if (rv == CKR_PIN_INCORRECT) {
			fprintf(stderr, "ERROR: The given user PIN does not match the one in the token.\n");
		}
		else
		{
			fprintf(stderr, "ERROR: Could not log in on the token.\n");
		}
		free(objID);
		return 1;
	}

	CK_OBJECT_HANDLE oHandle = searchObject(hSession, objID, objIDLen);
	if (oHandle != CK_INVALID_HANDLE && forceExec == 0)
	{
		free(objID);
		fprintf(stderr, "ERROR: The ID is already assigned to another object. "
				"Use --force to override this message.\n");
		return 1;
	}

	int result = crypto_import_key_pair(hSession, filePath, filePIN, label, objID, objIDLen, noPublicKey);

	free(objID);

	return result;
}

// Convert a char array of hexadecimal characters into a binary representation
char* hexStrToBin(char *objectID, int idLength, int *newLen)
{
	char *bytes = NULL;

	if (idLength % 2 != 0)
	{
		fprintf(stderr, "ERROR: Invalid length on hex string.\n");
		return NULL;
	}

	for (int i = 0; i < idLength; i++)
	{
		if (hexdigit_to_int(objectID[i]) == -1)
		{
			fprintf(stderr, "ERROR: Invalid character in hex string.\n");
			return NULL;
		}
	}

	*newLen = idLength / 2;
	bytes = (char *) malloc(*newLen);
	if (bytes == NULL)
	{
		fprintf(stderr, "ERROR: Could not allocate memory.\n");
		return NULL;
	}

	for (int i = 0; i < *newLen; i++)
	{
		bytes[i] = hexdigit_to_int(objectID[2*i]) * 16 +
				hexdigit_to_int(objectID[2*i+1]);
	}

	return bytes;
}

// Return the integer value of a hexadecimal character
int hexdigit_to_int(char ch)
{
	switch (ch)
	{
		case '0':
			return 0;
		case '1':
			return 1;
		case '2':
			return 2;
		case '3':
			return 3;
		case '4':
			return 4;
		case '5':
			return 5;
		case '6':
			return 6;
		case '7':
			return 7;
		case '8':
			return 8;
		case '9':
			return 9;
		case 'a':
		case 'A':
			return 10;
		case 'b':
		case 'B':
			return 11;
		case 'c':
		case 'C':
			return 12;
		case 'd':
		case 'D':
			return 13;
		case 'e':
		case 'E':
			return 14;
		case 'f':
		case 'F':
			return 15;
		default:
			return -1;
	}
}

// Search for an object
CK_OBJECT_HANDLE searchObject(CK_SESSION_HANDLE hSession, char *objID, int objIDLen)
{
	if (objID == NULL)
	{
		return CK_INVALID_HANDLE;
	}

	CK_OBJECT_CLASS oClass = CKO_PRIVATE_KEY;
	CK_OBJECT_HANDLE hObject = CK_INVALID_HANDLE;
	CK_ULONG objectCount = 0;

	CK_ATTRIBUTE objTemplate[] = {
		{ CKA_CLASS, &oClass, sizeof(oClass) },
		{ CKA_ID,    objID,   objIDLen }
	};

	CK_RV rv = p11->C_FindObjectsInit(hSession, objTemplate, 2);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not prepare the object search.\n");
		return CK_INVALID_HANDLE;
	}

	rv = p11->C_FindObjects(hSession, &hObject, 1, &objectCount);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not get the search results.\n");
		return CK_INVALID_HANDLE;
	}

	rv = p11->C_FindObjectsFinal(hSession);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not finalize the search.\n");
		return CK_INVALID_HANDLE;
	}

	if (objectCount == 0)
	{
		return CK_INVALID_HANDLE;
	}

	return hObject;
}
