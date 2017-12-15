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
 softhsm2-util.cpp

 This program can be used for interacting with HSMs using PKCS#11.
 The default library is the libsofthsm2.so
 *****************************************************************************/

#include <config.h>
#include "softhsm2-util.h"
#include "findslot.h"
#include "getpw.h"
#include "library.h"
#include "log.h"
#include "Configuration.h"
#include "SimpleConfigLoader.h"
#include "Directory.h"
#include "MutexFactory.h"
#include "ObjectStoreToken.h"
#include "OSPathSep.h"

#if defined(WITH_OPENSSL)
#include "OSSLCryptoFactory.h"
#else
#include "BotanCryptoFactory.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#else
#include <direct.h>
#include <io.h>
#endif
#include <iostream>
#include <fstream>

// Initialise the one-and-only instance

#ifdef HAVE_CXX11

std::unique_ptr<MutexFactory> MutexFactory::instance(nullptr);
std::unique_ptr<SecureMemoryRegistry> SecureMemoryRegistry::instance(nullptr);
#if defined(WITH_OPENSSL)
std::unique_ptr<OSSLCryptoFactory> OSSLCryptoFactory::instance(nullptr);
#else
std::unique_ptr<BotanCryptoFactory> BotanCryptoFactory::instance(nullptr);
#endif

#else

std::auto_ptr<MutexFactory> MutexFactory::instance(NULL);
std::auto_ptr<SecureMemoryRegistry> SecureMemoryRegistry::instance(NULL);
#if defined(WITH_OPENSSL)
std::auto_ptr<OSSLCryptoFactory> OSSLCryptoFactory::instance(NULL);
#else
std::auto_ptr<BotanCryptoFactory> BotanCryptoFactory::instance(NULL);
#endif

#endif

// Display the usage
void usage()
{
	printf("Support tool for PKCS#11\n");
	printf("Usage: softhsm2-util [ACTION] [OPTIONS]\n");
	printf("Action:\n");
	printf("  --delete-token    Delete the token at a given slot.\n");
	printf("                    Use with --token or --serial.\n");
	printf("                    WARNING: Any content in token will be erased.\n");
	printf("  -h                Shows this help screen.\n");
	printf("  --help            Shows this help screen.\n");
	printf("  --import <path>   Import a key pair from the given path.\n");
	printf("                    The file must be in PKCS#8-format.\n");
	printf("                    Use with --slot or --token or --serial, --file-pin,\n");
	printf("                    --label, --id, --no-public-key, and --pin.\n");
	printf("  --init-token      Initialize the token at a given slot.\n");
	printf("                    Use with --slot or --token or --serial or --free,\n");
	printf("                    --label, --so-pin, and --pin.\n");
	printf("                    WARNING: Any content in token will be erased.\n");
	printf("  --show-slots      Display all the available slots.\n");
	printf("  -v                Show version info.\n");
	printf("  --version         Show version info.\n");
	printf("Options:\n");
	printf("  --aes             Used to tell import to use file as is and import it as AES.\n");
	printf("  --file-pin <PIN>  Supply a PIN if the file is encrypted.\n");
	printf("  --force           Used to override a warning.\n");
	printf("  --free            Use the first free/uninitialized token.\n");
	printf("  --id <hex>        Defines the ID of the object. Hexadecimal characters.\n");
	printf("                    Use with --force if multiple key pairs may share\n");
	printf("                    the same ID.\n");
	printf("  --label <text>    Defines the label of the object or the token.\n");
	printf("  --module <path>   Use another PKCS#11 library than SoftHSM.\n");
	printf("  --no-public-key   Do not import the public key.\n");
	printf("  --pin <PIN>       The PIN for the normal user.\n");
	printf("  --serial <number> Will use the token with a matching serial number.\n");
	printf("  --slot <number>   The slot where the token is located.\n");
	printf("  --so-pin <PIN>    The PIN for the Security Officer (SO).\n");
	printf("  --token <label>   Will use the token with a matching token label.\n");
}

// Enumeration of the long options
enum {
	OPT_DELETE_TOKEN = 0x100,
	OPT_FILE_PIN,
	OPT_FORCE,
	OPT_FREE,
	OPT_HELP,
	OPT_ID,
	OPT_IMPORT,
	OPT_INIT_TOKEN,
	OPT_LABEL,
	OPT_MODULE,
	OPT_NO_PUBLIC_KEY,
	OPT_PIN,
	OPT_SERIAL,
	OPT_SHOW_SLOTS,
	OPT_SLOT,
	OPT_SO_PIN,
	OPT_TOKEN,
	OPT_VERSION,
	OPT_AES
};

// Text representation of the long options
static const struct option long_options[] = {
	{ "delete-token",    0, NULL, OPT_DELETE_TOKEN },
	{ "file-pin",        1, NULL, OPT_FILE_PIN },
	{ "force",           0, NULL, OPT_FORCE },
	{ "free",            0, NULL, OPT_FREE },
	{ "help",            0, NULL, OPT_HELP },
	{ "id",              1, NULL, OPT_ID },
	{ "import",          1, NULL, OPT_IMPORT },
	{ "init-token",      0, NULL, OPT_INIT_TOKEN },
	{ "label",           1, NULL, OPT_LABEL },
	{ "module",          1, NULL, OPT_MODULE },
	{ "no-public-key",   0, NULL, OPT_NO_PUBLIC_KEY },
	{ "pin",             1, NULL, OPT_PIN },
	{ "serial",          1, NULL, OPT_SERIAL },
	{ "show-slots",      0, NULL, OPT_SHOW_SLOTS },
	{ "slot",            1, NULL, OPT_SLOT },
	{ "so-pin",          1, NULL, OPT_SO_PIN },
	{ "token",           1, NULL, OPT_TOKEN },
	{ "version",         0, NULL, OPT_VERSION },
	{ "aes",             0, NULL, OPT_AES },
	{ NULL,              0, NULL, 0 }
};

CK_FUNCTION_LIST_PTR p11;

// The main function
int main(int argc, char* argv[])
{
	int option_index = 0;
	int opt;

	char* inPath = NULL;
	char* soPIN = NULL;
	char* userPIN = NULL;
	char* filePIN = NULL;
	char* label = NULL;
	char* module = NULL;
	char* objectID = NULL;
	char* slot = NULL;
	char* serial = NULL;
	char* token = NULL;
	char* errMsg = NULL;
	int forceExec = 0;
	bool freeToken = false;
	int noPublicKey = 0;
	bool importAES = false;

	int doInitToken = 0;
	int doShowSlots = 0;
	int doImport = 0;
	int doDeleteToken = 0;
	int action = 0;
	bool needP11 = false;
	int rv = 0;
	CK_SLOT_ID slotID = 0;

	moduleHandle = NULL;
	p11 = NULL;

	while ((opt = getopt_long(argc, argv, "hv", long_options, &option_index)) != -1)
	{
		switch (opt)
		{
			case OPT_SHOW_SLOTS:
				doShowSlots = 1;
				action++;
				needP11 = true;
				break;
			case OPT_INIT_TOKEN:
				doInitToken = 1;
				action++;
				needP11 = true;
				break;
			case OPT_IMPORT:
				doImport = 1;
				action++;
				inPath = optarg;
				needP11 = true;
				break;
			case OPT_AES:
				importAES = true;
				break;
			case OPT_DELETE_TOKEN:
				doDeleteToken = 1;
				action++;
				break;
			case OPT_SLOT:
				slot = optarg;
				break;
			case OPT_LABEL:
				label = optarg;
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
			case OPT_FREE:
				freeToken = true;
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
	if (action != 1)
	{
		usage();
		exit(1);
	}

	if (needP11)
	{
		// Check the basic setup of SoftHSM
		if (!checkSetup())
		{
			fprintf(stderr, "ERROR: Please verify that the SoftHSM configuration is correct.\n");
			exit(1);
		}

		// Get a pointer to the function list for PKCS#11 library
		CK_C_GetFunctionList pGetFunctionList = loadLibrary(module, &moduleHandle, &errMsg);
		if (!pGetFunctionList)
		{
			fprintf(stderr, "ERROR: Could not load the PKCS#11 library/module: %s\n", errMsg);
			fprintf(stderr, "ERROR: Please check log files for additional information.\n");
			exit(1);
		}

		// Load the function list
		(*pGetFunctionList)(&p11);

		// Initialize the library
		CK_RV p11rv = p11->C_Initialize(NULL_PTR);
		if (p11rv != CKR_OK)
		{
			fprintf(stderr, "ERROR: Could not initialize the PKCS#11 library/module: %s\n", module ? module : DEFAULT_PKCS11_LIB);
			fprintf(stderr, "ERROR: Please check log files for additional information.\n");
			exit(1);
		}
	}

	// We should create the token.
	if (doInitToken)
	{
		// Get the slotID
		rv = findSlot(slot, serial, token, freeToken, slotID);
		if (!rv)
		{
			rv = initToken(slotID, label, soPIN, userPIN);
		}
	}

	// Show all available slots
	if (!rv && doShowSlots)
	{
		rv = showSlots();
	}

	// Import a key pair from the given path
	if (!rv && doImport)
	{
		// Get the slotID
		rv = findSlot(slot, serial, token, slotID);
		if (!rv)
		{
			rv = importAES ? importSecretKey(inPath, slotID, userPIN, label, objectID)
					: importKeyPair(inPath, filePIN, slotID, userPIN, label, objectID, forceExec, noPublicKey);
		}
	}

	// We should delete the token.
	if (!rv && doDeleteToken)
	{
		if (deleteToken(serial, token))
		{
			rv = 0;
		}
		else
		{
			rv = 1;
		}
	}

	// Finalize the library
	if (needP11)
	{
		p11->C_Finalize(NULL_PTR);
		unloadLibrary(moduleHandle);
	}

	return rv;
}

// Check the basic setup of SoftHSM
bool checkSetup()
{
	// Initialize the SoftHSM internal functions
	if (!initSoftHSM())
	{
		finalizeSoftHSM();
		return false;
	}

	std::string basedir = Configuration::i()->getString("directories.tokendir", DEFAULT_TOKENDIR);

	// Try open the token directory
	Directory storeDir(basedir);
	if (!storeDir.isValid())
	{
		fprintf(stderr, "ERROR: Failed to enumerate object store in %s\n", basedir.c_str());
		finalizeSoftHSM();
		return false;
	}

	finalizeSoftHSM();
	return true;
}

// Initialize the token
int initToken(CK_SLOT_ID slotID, char* label, char* soPIN, char* userPIN)
{
	char so_pin_copy[MAX_PIN_LEN+1];
	char user_pin_copy[MAX_PIN_LEN+1];

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
	if (getPW(soPIN, so_pin_copy, CKU_SO) != 0)
	{
		fprintf(stderr, "ERROR: Could not get SO PIN\n");
		return 1;
	}
	if (getPW(userPIN, user_pin_copy, CKU_USER) != 0)
	{
		fprintf(stderr, "ERROR: Could not get user PIN\n");
		return 1;
	}

	// Load the variables
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
			fprintf(stderr, "ERROR rv=0x%08X: Could not initialize the token.\n", (unsigned int)rv);
			fprintf(stderr, "Please check log files for additional information.\n");
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

	// Get the token info
	CK_TOKEN_INFO tokenInfo;
	rv = p11->C_GetTokenInfo(slotID, &tokenInfo);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not get info about the initialized token in slot %lu.\n", slotID);
		return 1;
	}

	// Reload the library
	p11->C_Finalize(NULL_PTR);
	rv = p11->C_Initialize(NULL_PTR);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not initialize the library.\n");
		return 1;
	}

	// Get the slotID
	CK_SLOT_ID newSlotID;
	if (findSlot(tokenInfo, newSlotID))
	{
		return 1;
	}

	if (slotID == newSlotID)
	{
		printf("The token has been initialized on slot %lu\n", newSlotID);
	}
	else
	{
		printf("The token has been initialized and is reassigned to slot %lu\n", newSlotID);
	}

	return 0;
}

// Delete the token
bool deleteToken(char* serial, char* token)
{
	if (serial == NULL && token == NULL)
	{
		fprintf(stderr, "ERROR: A token must be supplied. "
				"Use --serial <serial> or --token <label>\n");
		return false;
	}

	// Initialize the SoftHSM internal functions
	if (!initSoftHSM())
	{
		finalizeSoftHSM();
		return false;
	}

	bool rv = true;
	std::string basedir = Configuration::i()->getString("directories.tokendir", DEFAULT_TOKENDIR);
	std::string tokendir;

	rv = findTokenDirectory(basedir, tokendir, serial, token);

	if (rv)
	{
		std::string fulldir = basedir;
		if (fulldir.find_last_of(OS_PATHSEP) != (fulldir.size()-1))
		{
			fulldir += OS_PATHSEP + tokendir;
		}
		else
		{
			fulldir += tokendir;
		}

		rv = rmdir(fulldir);
		if (rv)
		{
			printf("The token (%s) has been deleted.\n", fulldir.c_str());
		}
	}

	finalizeSoftHSM();

	return rv;
}

bool initSoftHSM()
{
	// Not using threading
	MutexFactory::i()->disable();

	// Initiate SecureMemoryRegistry
	if (SecureMemoryRegistry::i() == NULL)
	{
		fprintf(stderr, "ERROR: Could not initiate SecureMemoryRegistry.\n");
		return false;
	}

	// Build the CryptoFactory
	if (CryptoFactory::i() == NULL)
	{
		fprintf(stderr, "ERROR: Could not initiate CryptoFactory.\n");
		return false;
	}

#ifdef WITH_FIPS
	// Check the FIPS status
	if (!CryptoFactory::i()->getFipsSelfTestStatus())
	{
		fprintf(stderr, "ERROR: FIPS self test failed.\n");
		return false;
	}
#endif

	// Load the configuration
	if (!Configuration::i()->reload(SimpleConfigLoader::i()))
	{
		fprintf(stderr, "ERROR: Could not load the SoftHSM configuration.\n");
		return false;
	}

	// Configure the log level
	if (!setLogLevel(Configuration::i()->getString("log.level", DEFAULT_LOG_LEVEL)))
	{
		fprintf(stderr, "ERROR: Could not configure the log level.\n");
		return false;
	}

	// Configure object store storage backend used by all tokens.
	if (!ObjectStoreToken::selectBackend(Configuration::i()->getString("objectstore.backend", DEFAULT_OBJECTSTORE_BACKEND)))
	{
		fprintf(stderr, "ERROR: Could not select token backend.\n");
		return false;
	}

	return true;
}

void finalizeSoftHSM()
{
	CryptoFactory::reset();
	SecureMemoryRegistry::reset();
}

// Find the token directory
bool findTokenDirectory(std::string basedir, std::string& tokendir, char* serial, char* label)
{
	if (serial == NULL && label == NULL)
	{
		return false;
	}

	// Load the variables
	CK_UTF8CHAR paddedSerial[16];
	CK_UTF8CHAR paddedLabel[32];
	if (serial != NULL)
	{
		size_t inSize = strlen(serial);
		size_t outSize = sizeof(paddedSerial);
		if (inSize > outSize)
		{
			fprintf(stderr, "ERROR: --serial is too long.\n");
			return false;
		}
		memset(paddedSerial, ' ', outSize);
		memcpy(paddedSerial, serial, inSize);
	}
	if (label != NULL)
	{
		size_t inSize = strlen(label);
		size_t outSize = sizeof(paddedLabel);
		if (inSize > outSize)
		{
			fprintf(stderr, "ERROR: --token is too long.\n");
			return false;
		}
		memset(paddedLabel, ' ', outSize);
		memcpy(paddedLabel, label, inSize);
	}

	// Find all tokens in the specified path
	Directory storeDir(basedir);

	if (!storeDir.isValid())
	{
		fprintf(stderr, "Failed to enumerate object store in %s\n", basedir.c_str());

		return false;
	}

	// Assume that all subdirectories are tokens
	std::vector<std::string> dirs = storeDir.getSubDirs();

	ByteString tokenLabel;
	ByteString tokenSerial;
	CK_UTF8CHAR paddedTokenSerial[16];
	CK_UTF8CHAR paddedTokenLabel[32];
	size_t counter = 0;
	for (std::vector<std::string>::iterator i = dirs.begin(); i != dirs.end(); i++)
	{
		memset(paddedTokenSerial, ' ', sizeof(paddedTokenSerial));
		memset(paddedTokenLabel, ' ', sizeof(paddedTokenLabel));

		// Create a token instance
		ObjectStoreToken* token = ObjectStoreToken::accessToken(basedir, *i);

		if (!token->isValid())
		{
			delete token;
			continue;
		}

		if (token->getTokenLabel(tokenLabel) && tokenLabel.size() <= sizeof(paddedTokenLabel))
		{
			strncpy((char*) paddedTokenLabel, (char*) tokenLabel.byte_str(), tokenLabel.size());
		}
		if (token->getTokenSerial(tokenSerial) && tokenSerial.size() <= sizeof(paddedTokenSerial))
		{
			strncpy((char*) paddedTokenSerial, (char*) tokenSerial.byte_str(), tokenSerial.size());
		}

		if (serial != NULL && label == NULL &&
			memcmp(paddedTokenSerial, paddedSerial, sizeof(paddedSerial)) == 0)
		{
			printf("Found token (%s) with matching serial.\n", i->c_str());
			tokendir = i->c_str();
			counter++;
		}
		if (serial == NULL && label != NULL &&
			memcmp(paddedTokenLabel, paddedLabel, sizeof(paddedLabel)) == 0)
		{
			printf("Found token (%s) with matching token label.\n", i->c_str());
			tokendir = i->c_str();
			counter++;
		}
		if (serial != NULL && label != NULL &&
			memcmp(paddedTokenSerial, paddedSerial, sizeof(paddedSerial)) == 0 &&
			memcmp(paddedTokenLabel, paddedLabel, sizeof(paddedLabel)) == 0)
		{
			printf("Found token (%s) with matching serial and token label.\n", i->c_str());
			tokendir = i->c_str();
			counter++;
		}

		delete token;
	}

	if (counter == 1) return true;
	if (counter > 1)
	{
		fprintf(stderr, "ERROR: Found multiple matching tokens.\n");
		return false;
	}

	fprintf(stderr, "ERROR: Could not find a token using --serial or --token.\n");
	return false;
}


// Delete a directory
bool rmdir(std::string path)
{
	bool rv = true;

#ifndef _WIN32
	// Enumerate the directory
	DIR* dir = opendir(path.c_str());

	if (dir == NULL)
	{
		fprintf(stderr, "ERROR: Failed to open directory %s\n", path.c_str());
		return false;
	}

	// Enumerate the directory
	struct dirent* entry = NULL;

	while ((entry = readdir(dir)) != NULL)
	{
		bool handled = false;

		// Check if this is the . or .. entry
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
		{
			continue;
		}

		// Convert the name of the entry to a C++ string
		std::string name(entry->d_name);
		std::string fullPath = path + OS_PATHSEP + name;

#if defined(_DIRENT_HAVE_D_TYPE) && defined(_BSD_SOURCE)
		// Determine the type of the entry
		switch(entry->d_type)
		{
			case DT_DIR:
				// This is a directory
				rv = rmdir(fullPath);
				handled = true;
				break;
			case DT_REG:
				// This is a regular file
				rv = rm(fullPath);
				handled = true;
				break;
			default:
				break;
		}
#endif

		if (rv == false)
			break;

		if (!handled)
		{
			// The entry type has to be determined using lstat
			struct stat entryStatus;

			if (!lstat(fullPath.c_str(), &entryStatus))
			{
				if (S_ISDIR(entryStatus.st_mode))
				{
					// This is a directory
					rv = rmdir(fullPath);
				}
				else if (S_ISREG(entryStatus.st_mode))
				{
					// This is a regular file
					rv = rm(fullPath);
				}
			}

			if (rv == false)
				break;
		}
	}

	// Close the directory
	closedir(dir);
#else
	// Enumerate the directory
	std::string pattern;
	intptr_t h;
	struct _finddata_t fi;

	if ((path.back() == '/') || (path.back() == '\\'))
		pattern = path + "*";
	else
		pattern = path + "/*";
	memset(&fi, 0, sizeof(fi));
	h = _findfirst(pattern.c_str(), &fi);
	if (h == -1)
	{
		// empty directory
		if (errno == ENOENT)
			goto finished;

		fprintf(stderr, "ERROR: Failed to open directory %s\n", path.c_str());

		return false;
	}

	// scan files & subdirs
	do
	{
		// Check if this is the . or .. entry
		if (!strcmp(fi.name, ".") || !strcmp(fi.name, ".."))
			continue;

		std::string fullPath = path + OS_PATHSEP + fi.name;
		if ((fi.attrib & _A_SUBDIR) == 0)
		{
			// This is a regular file
			rv = rm(fullPath);
		}
		else
		{
			// This is a directory
			rv = rmdir(fullPath);
		}

		memset(&fi, 0, sizeof(fi));

		if (rv == false)
			break;
	} while (_findnext(h, &fi) == 0);

	(void) _findclose(h);

    finished:
#endif

	if (rv == false)
		return false;

	int result;
#ifndef _WIN32
	result = ::rmdir(path.c_str());
#else
	result = _rmdir(path.c_str());
#endif

	if (result != 0)
	{
		fprintf(stderr, "ERROR: Could not delete the directory: %s\n", path.c_str());
		return false;
	}

	return true;
}

// Delete a file
bool rm(std::string path)
{
	int result;

#ifndef _WIN32
	result = ::remove(path.c_str());
#else
	result = _unlink(path.c_str());
#endif

	if (result != 0)
	{
		fprintf(stderr, "ERROR: Could not delete the file: %s\n", path.c_str());
		return false;
	}

	return true;
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

	for (CK_ULONG i = 0; i < ulSlotCount; i++)
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
	char* filePath,
	char* filePIN,
	CK_SLOT_ID slotID,
	char* userPIN,
	char* label,
	char* objectID,
	int forceExec,
	int noPublicKey
)
{
	char user_pin_copy[MAX_PIN_LEN+1];

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

	size_t objIDLen = 0;
	char* objID = hexStrToBin(objectID, strlen(objectID), &objIDLen);
	if (objID == NULL)
	{
		fprintf(stderr, "Please edit --id <hex> to correct error.\n");
		return 1;
	}

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
	if (getPW(userPIN, user_pin_copy, CKU_USER) != 0)
	{
		fprintf(stderr, "ERROR: Could not get user PIN\n");
		free(objID);
		return 1;
	}

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

	crypto_init();
	int result = crypto_import_key_pair(hSession, filePath, filePIN, label, objID, objIDLen, noPublicKey);
	crypto_final();

	free(objID);

	return result;
}

// Import a secret key from given path
int importSecretKey(char* filePath, CK_SLOT_ID slotID, char* userPIN, char* label, char* objectID)
{
	char user_pin_copy[MAX_PIN_LEN+1];

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

	size_t objIDLen = 0;
	char* objID = hexStrToBin(objectID, strlen(objectID), &objIDLen);
	if (objID == NULL)
	{
		fprintf(stderr, "Please edit --id <hex> to correct error.\n");
		return 1;
	}

	// Get the password
	if (getPW(userPIN, user_pin_copy, CKU_USER) != 0)
	{
		fprintf(stderr, "ERROR: Could not get user PIN\n");
		return 1;
	}

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
		return 1;
	}

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
		return 1;
	}

	crypto_init();
	int result = crypto_import_aes_key(hSession, filePath, label, objID, objIDLen);
	crypto_final();

	return result;
}

// Convert a char array of hexadecimal characters into a binary representation
char* hexStrToBin(char* objectID, int idLength, size_t* newLen)
{
	char* bytes = NULL;

	if (idLength < 2 || idLength % 2 != 0)
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
	bytes = (char*) malloc(*newLen);
	if (bytes == NULL)
	{
		fprintf(stderr, "ERROR: Could not allocate memory.\n");
		return NULL;
	}

	for (size_t i = 0; i < *newLen; i++)
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
CK_OBJECT_HANDLE searchObject(CK_SESSION_HANDLE hSession, char* objID, size_t objIDLen)
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
