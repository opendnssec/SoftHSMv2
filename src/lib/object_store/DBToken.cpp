/*
 * Copyright (c) 2013 SURFnet bv
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
 DBToken.cpp
 
 The token class; a token is stored in a directory containing a single
 database file.
 Each object is stored in multiple tables with every attribute base type
 stored in a different table.
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSAttributes.h"
#include "OSAttribute.h"
#include "OSPathSep.h"

#include "cryptoki.h"
#include "DBToken.h"
#include "DBObject.h"
#include "DB.h"

#include "Directory.h"

#include <vector>
#include <string>
#include <set>
#include <map>
#include <list>
#include <cstdio>
#include <sys/stat.h>
#include <errno.h>

const char * const DBTOKEN_FILE = "sqlite3.db";
const long long DBTOKEN_OBJECT_TOKENINFO = 1;

// Constructor for creating a new token.
DBToken::DBToken(const std::string &baseDir, const std::string &tokenName, const ByteString &label, const ByteString &serial)
	: _connection(NULL), _tokenMutex(NULL)
{
	std::string tokenDir = baseDir + OS_PATHSEP + tokenName;
	std::string tokenPath = tokenDir + OS_PATHSEP + DBTOKEN_FILE;

	// Refuse to open an already existing database.
	FILE *f = fopen(tokenPath.c_str(),"r");
	if (f)
	{
		fclose(f);
		ERROR_MSG("Refusing to overwrite and existing database at \"%s\"", tokenPath.c_str());
		return;
	}

	// First create the directory for the token, we expect basePath to already exist
	if (mkdir(tokenDir.c_str(), S_IFDIR | S_IRWXU))
	{
		// Allow the directory to exists already.
		if (errno != EEXIST)
		{
			ERROR_MSG("Unable to create directory \"%s\"", tokenDir.c_str());
			return;
		}
	}

	// Create
	_connection = DB::Connection::Create(tokenDir, DBTOKEN_FILE);
	if (_connection == NULL)
	{
		ERROR_MSG("Failed to create a database connection for \"%s\"", tokenPath.c_str());
		return;
	}

	if (!_connection->connect())
	{
		delete _connection;
		_connection = NULL;

		ERROR_MSG("Failed to connect to the database at \"%s\"", tokenPath.c_str());

		// Now remove the token directory
		if (remove(tokenDir.c_str()))
		{
			ERROR_MSG("Failed to remove the token directory \"%s\"", tokenDir.c_str());
		}

		return;
	}

	// Create a DBObject for the established connection to the database.
	DBObject tokenObject(_connection);

	// First create the tables that support storage of object attributes and then insert the object containing
	// the token info into the database.
	if (!tokenObject.createTables() || !tokenObject.insert() || tokenObject.objectId()!=DBTOKEN_OBJECT_TOKENINFO)
	{
		tokenObject.dropConnection();

		_connection->close();
		delete _connection;
		_connection = NULL;

		ERROR_MSG("Failed to create tables for storing objects in database at \"%s\"", tokenPath.c_str());
		return;
	}

	// Set the initial attributes
	CK_ULONG flags =
		CKF_RNG |
		CKF_LOGIN_REQUIRED | // FIXME: check
		CKF_RESTORE_KEY_NOT_NEEDED |
		CKF_TOKEN_INITIALIZED |
		CKF_SO_PIN_LOCKED |
		CKF_SO_PIN_TO_BE_CHANGED;

	OSAttribute tokenLabel(label);
	OSAttribute tokenSerial(serial);
	OSAttribute tokenFlags(flags);

	if (!tokenObject.setAttribute(CKA_OS_TOKENLABEL, tokenLabel) ||
		!tokenObject.setAttribute(CKA_OS_TOKENSERIAL, tokenSerial) ||
		!tokenObject.setAttribute(CKA_OS_TOKENFLAGS, tokenFlags))
	{
		_connection->close();
		delete _connection;
		_connection = NULL;

		// Now remove the token file
		if (remove(tokenPath.c_str()))
		{
			ERROR_MSG("Failed to remove the token file at \"%s\"", tokenPath.c_str());
		}

		// Now remove the token directory
		if (remove(tokenDir.c_str()))
		{
			ERROR_MSG("Failed to remove the token directory at \"%s\"", tokenDir.c_str());
		}
		return;
	}

	_tokenMutex = MutexFactory::i()->getMutex();
	// Success!
}

// Constructor for accessing an existing token.
DBToken::DBToken(const std::string &baseDir, const std::string &tokenName)
	: _connection(NULL), _tokenMutex(NULL)
{
	std::string tokenDir = baseDir + OS_PATHSEP + tokenName;
	std::string tokenPath = tokenDir + OS_PATHSEP + DBTOKEN_FILE;

	// Refuse to open an already existing database.
	FILE *f = fopen(tokenPath.c_str(),"r");
	if (f == NULL)
	{
		ERROR_MSG("Refusing to open a non-existant database at \"%s\"", tokenPath.c_str());
		return;
	}
	fclose(f);

	// Create a database connection.
	_connection = DB::Connection::Create(tokenDir, DBTOKEN_FILE);
	if (_connection == NULL)
	{
		ERROR_MSG("Failed to create a database connection for \"%s\"", tokenPath.c_str());
		return;
	}

	if (!_connection->connect())
	{
		delete _connection;
		_connection = NULL;

		ERROR_MSG("Failed to connect to the database at \"%s\"", tokenPath.c_str());

		return;
	}

	// Find the DBObject for the established connection to the database.
	DBObject tokenObject(_connection);

	// First find the token obect that indicates the token is properly initialized.
	if (!tokenObject.find(DBTOKEN_OBJECT_TOKENINFO))
	{
		tokenObject.dropConnection();

		_connection->close();
		delete _connection;
		_connection = NULL;

		ERROR_MSG("Failed to open token object in the token database at \"%s\"", tokenPath.c_str());
		return;
	}

	_tokenMutex = MutexFactory::i()->getMutex();

	// Success!
}

DBToken *DBToken::createToken(const std::string basePath, const std::string tokenDir, const ByteString &label, const ByteString &serial)
{
	Directory baseDir(basePath);

	if (!baseDir.isValid())
	{
		return NULL;
	}

	// Create the token directory
	if (!baseDir.mkdir(tokenDir))
	{
		return NULL;
	}

	DBToken *token = new DBToken(basePath, tokenDir, label, serial);
	if (!token->isValid())
	{
		baseDir.rmdir(tokenDir);

		delete token;
		return NULL;
	}

	DEBUG_MSG("Created new token %s", tokenDir.c_str());

	return token;
}

DBToken *DBToken::accessToken(const std::string &basePath, const std::string &tokenDir)
{
	return new DBToken(basePath, tokenDir);
}

// Destructor
DBToken::~DBToken()
{
	if (_tokenMutex)
	{
		MutexFactory::i()->recycleMutex(_tokenMutex);
		_tokenMutex = NULL;
	}

	std::map<long long, OSObject*> cleanUp = _allObjects;
	_allObjects.clear();
	for (std::map<long long, OSObject*>::iterator i = cleanUp.begin(); i != cleanUp.end(); ++i)
	{
		delete i->second;
	}

	if (_connection)
	{
		delete _connection;
		_connection = NULL;
	}
}

// Set the SO PIN
bool DBToken::setSOPIN(const ByteString& soPINBlob)
{
	if (_connection == NULL) return false;

	// Create a DBObject for the established connection to the token object in the database
	DBObject tokenObject(_connection);

	if (!tokenObject.startTransaction(DBObject::ReadWrite))
	{
		ERROR_MSG("Unable to start a transaction for updating the SOPIN and TOKENFLAGS in token database at \"%s\"", _connection->dbpath().c_str());
		return false;
	}

	// First find the token object in the database.
	if (!tokenObject.find(DBTOKEN_OBJECT_TOKENINFO))
	{
		ERROR_MSG("Token object not found in token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	OSAttribute soPIN(soPINBlob);
	if (!tokenObject.setAttribute(CKA_OS_SOPIN, soPIN))
	{
		ERROR_MSG("Error while setting SOPIN in token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	if (!tokenObject.attributeExists(CKA_OS_TOKENFLAGS))
	{
		ERROR_MSG("Error while getting TOKENFLAGS from token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	// Retrieve flags from the database and reset flags related to tries and expiration of the SOPIN.
	CK_ULONG flags = tokenObject.getAttribute(CKA_OS_TOKENFLAGS).getUnsignedLongValue()
					& ~(CKF_SO_PIN_COUNT_LOW | CKF_SO_PIN_FINAL_TRY | CKF_SO_PIN_LOCKED | CKF_SO_PIN_TO_BE_CHANGED);

	OSAttribute changedTokenFlags(flags);
	if (!tokenObject.setAttribute(CKA_OS_TOKENFLAGS, changedTokenFlags))
	{
		ERROR_MSG("Error while setting TOKENFLAGS in token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	if (!tokenObject.commitTransaction())
	{
		ERROR_MSG("Error while committing SOPIN and TOKENFLAGS changes to token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	return true;
}

// Get the SO PIN
bool DBToken::getSOPIN(ByteString& soPINBlob)
{
	if (_connection == NULL) return false;

	// Create a DBObject for the established connection to the token object in the database
	DBObject tokenObject(_connection);

	if (!tokenObject.startTransaction(DBObject::ReadOnly))
	{
		ERROR_MSG("Unable to start a transaction for getting the SOPIN from token database at \"%s\"", _connection->dbpath().c_str());
		return false;
	}

	// First find the token object in the database.
	if (!tokenObject.find(DBTOKEN_OBJECT_TOKENINFO))
	{
		ERROR_MSG("Token object not found in token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	if (!tokenObject.attributeExists(CKA_OS_SOPIN))
	{
		ERROR_MSG("Error while getting SOPIN from token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	tokenObject.commitTransaction();
	soPINBlob = tokenObject.getAttribute(CKA_OS_SOPIN).getByteStringValue();
	return true;
}

// Set the user PIN
bool DBToken::setUserPIN(ByteString userPINBlob)
{
	if (_connection == NULL) return false;

	// Create a DBObject for the established connection to the token object in the database
	DBObject tokenObject(_connection);

	if (!tokenObject.startTransaction(DBObject::ReadWrite))
	{
		ERROR_MSG("Unable to start a transaction for updating the USERPIN and TOKENFLAGS in token database at \"%s\"", _connection->dbpath().c_str());
		return false;
	}

	// First find the token object in the database.
	if (!tokenObject.find(DBTOKEN_OBJECT_TOKENINFO))
	{
		ERROR_MSG("Token object not found in token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	OSAttribute userPIN(userPINBlob);
	if (!tokenObject.setAttribute(CKA_OS_USERPIN, userPIN))
	{
		ERROR_MSG("Error while setting USERPIN in token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	if (!tokenObject.attributeExists(CKA_OS_TOKENFLAGS))
	{
		ERROR_MSG("Error while getting TOKENFLAGS from token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	// Retrieve flags from the database and reset flags related to tries and expiration of the SOPIN.
	CK_ULONG flags = tokenObject.getAttribute(CKA_OS_TOKENFLAGS).getUnsignedLongValue()
					| (CKF_USER_PIN_INITIALIZED & ~(CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY | CKF_USER_PIN_LOCKED | CKF_USER_PIN_TO_BE_CHANGED));

	OSAttribute changedTokenFlags(flags);
	if (!tokenObject.setAttribute(CKA_OS_TOKENFLAGS, changedTokenFlags))
	{
		ERROR_MSG("Error while setting TOKENFLAGS in token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	if (!tokenObject.commitTransaction())
	{
		ERROR_MSG("Error while committing USERPIN and TOKENFLAGS changes to token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	return true;
}

// Get the user PIN
bool DBToken::getUserPIN(ByteString& userPINBlob)
{
	if (_connection == NULL) return false;

	// Create a DBObject for the established connection to the token object in the database
	DBObject tokenObject(_connection);

	if (!tokenObject.startTransaction(DBObject::ReadOnly))
	{
		ERROR_MSG("Unable to start a transaction for getting the USERPIN from token database at \"%s\"", _connection->dbpath().c_str());
		return false;
	}

	// First find the token object in the database.
	if (!tokenObject.find(DBTOKEN_OBJECT_TOKENINFO))
	{
		ERROR_MSG("Token object not found in token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	if (!tokenObject.attributeExists(CKA_OS_USERPIN))
	{
		ERROR_MSG("Error while getting USERPIN from token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	tokenObject.commitTransaction();
	userPINBlob = tokenObject.getAttribute(CKA_OS_USERPIN).getByteStringValue();
	return true;
}

// Retrieve the token label
bool DBToken::getTokenLabel(ByteString& label)
{
	if (_connection == NULL) return false;

	// Create a DBObject for the established connection to the token object in the database
	DBObject tokenObject(_connection);

	if (!tokenObject.startTransaction(DBObject::ReadOnly))
	{
		ERROR_MSG("Unable to start a transaction for getting the TOKENLABEL from token database at \"%s\"", _connection->dbpath().c_str());
		return false;
	}

	// First find the token object in the database.
	if (!tokenObject.find(DBTOKEN_OBJECT_TOKENINFO))
	{
		ERROR_MSG("Token object not found in token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	if (!tokenObject.attributeExists(CKA_OS_TOKENLABEL))
	{
		ERROR_MSG("Error while getting TOKENLABEL from token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	tokenObject.commitTransaction();
	label = tokenObject.getAttribute(CKA_OS_TOKENLABEL).getByteStringValue();
	return true;
}

// Retrieve the token serial
bool DBToken::getTokenSerial(ByteString& serial)
{
	if (_connection == NULL) return false;

	// Create a DBObject for the established connection to the token object in the database
	DBObject tokenObject(_connection);

	if (!tokenObject.startTransaction(DBObject::ReadOnly))
	{
		ERROR_MSG("Unable to start a transaction for getting the TOKENSERIAL from token database at \"%s\"", _connection->dbpath().c_str());
		return false;
	}

	// First find the token object in the database.
	if (!tokenObject.find(DBTOKEN_OBJECT_TOKENINFO))
	{
		ERROR_MSG("Token object not found in token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	if (!tokenObject.attributeExists(CKA_OS_TOKENSERIAL))
	{
		ERROR_MSG("Error while getting TOKENSERIAL from token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	tokenObject.commitTransaction();
	serial = tokenObject.getAttribute(CKA_OS_TOKENSERIAL).getByteStringValue();
	return true;
}

// Get the token flags
bool DBToken::getTokenFlags(CK_ULONG& flags)
{
	if (_connection == NULL) return false;

	// Create a DBObject for the established connection to the token object in the database
	DBObject tokenObject(_connection);

	if (!tokenObject.startTransaction(DBObject::ReadOnly))
	{
		ERROR_MSG("Unable to start a transaction for updating the SOPIN and TOKENFLAGS in token database at \"%s\"", _connection->dbpath().c_str());
		return false;
	}

	// First find the token object in the database.
	if (!tokenObject.find(DBTOKEN_OBJECT_TOKENINFO))
	{
		ERROR_MSG("Token object not found in token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	if (!tokenObject.attributeExists(CKA_OS_TOKENFLAGS))
	{
		ERROR_MSG("Error while getting TOKENFLAGS from token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	tokenObject.commitTransaction();
	flags = tokenObject.getAttribute(CKA_OS_TOKENFLAGS).getUnsignedLongValue();
	return true;
}

// Set the token flags
bool DBToken::setTokenFlags(const CK_ULONG flags)
{
	if (_connection == NULL) return false;

	// Create a DBObject for the established connection to the token object in the database
	DBObject tokenObject(_connection);

	if (!tokenObject.startTransaction(DBObject::ReadWrite))
	{
		ERROR_MSG("Unable to start a transaction for setting the TOKENFLAGS in token database at \"%s\"", _connection->dbpath().c_str());
		return false;
	}

	// First find the token object in the database.
	if (!tokenObject.find(DBTOKEN_OBJECT_TOKENINFO))
	{
		ERROR_MSG("Token object not found in token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	OSAttribute tokenFlags(flags);
	if (!tokenObject.setAttribute(CKA_OS_TOKENFLAGS, tokenFlags))
	{
		ERROR_MSG("Error while setting TOKENFLAGS in token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	if (!tokenObject.commitTransaction())
	{
		ERROR_MSG("Error while committing TOKENFLAGS changes to token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	return true;
}

// Retrieve objects
std::set<OSObject *> DBToken::getObjects()
{
	std::set<OSObject*> objects;
	getObjects(objects);
	return objects;
}

void DBToken::getObjects(std::set<OSObject*> &objects)
{
	if (_connection == NULL) return;

	if (!_connection->beginTransactionRO()) return;

	DB::Statement statement = _connection->prepare("select id from object limit -1 offset 1");

	DB::Result result = _connection->perform(statement);

	if (result.isValid())
	{
		do {
			long long objectId = result.getLongLong(1);
			{
				MutexLocker lock(_tokenMutex);
				std::map<long long, OSObject*>::iterator it = _allObjects.find(objectId);
				if (it == _allObjects.end())
				{
					DBObject *object = new DBObject(_connection, this, objectId);
					_allObjects[objectId] = object;
					objects.insert(object);
				}
				else
				{
					objects.insert(it->second);
				}
			}
		} while (result.nextRow());
	}

	_connection->endTransactionRO();
}

// Create a new object
OSObject *DBToken::createObject()
{
	if (_connection == NULL) return NULL;

	DBObject *newObject = new DBObject(_connection, this);
	if (newObject == NULL)
	{
		ERROR_MSG("Failed to create an object: out of memory");
		return NULL;
	}

	if (!newObject->startTransaction(DBObject::ReadWrite))
	{
		delete newObject;
		ERROR_MSG("Unable to start a transaction in token database at \"%s\"", _connection->dbpath().c_str());
		return NULL;
	}

	if (!newObject->insert())
	{
		newObject->abortTransaction();
		delete newObject;
		ERROR_MSG("Unable to insert an object into token database at \"%s\"", _connection->dbpath().c_str());
		return NULL;
	}

	if (!newObject->isValid())
	{
		newObject->abortTransaction();
		delete newObject;
		ERROR_MSG("Object that was inserted in not valid");
		return NULL;
	}

	if (!newObject->commitTransaction())
	{
		newObject->abortTransaction();
		delete newObject;
		ERROR_MSG("Unable to commit a created object to token database at \"%s\"", _connection->dbpath().c_str());
		return NULL;
	}

	// Now add the new object to the list of existing objects.
	{
		MutexLocker lock(_tokenMutex);
		_allObjects[newObject->objectId()] = newObject;
	}

	return newObject;
}

bool DBToken::deleteObject(OSObject *object)
{
	if (_connection == NULL) return false;

	if (object == NULL)
	{
		ERROR_MSG("Object passed in as a parameter is NULL");
		return false;
	}

	if (!object->startTransaction(DBObject::ReadWrite))
	{
		ERROR_MSG("Unable to start a transaction for deleting an object in token database at \"%s\"", _connection->dbpath().c_str());
		return false;
	}

	if (!static_cast<DBObject *>(object)->remove())
	{
		ERROR_MSG("Error while deleting an existing object from the token database at \"%s\"", _connection->dbpath().c_str());
		object->abortTransaction();
		return false;
	}

	if (!object->commitTransaction())
	{
		ERROR_MSG("Error while committing the deletion of an existing object in token database at \"%s\"", _connection->dbpath().c_str());
		object->abortTransaction();
		return false;
	}

	return true;
}

// Checks if the token is consistent
bool DBToken::isValid()
{
	return _connection != NULL && _connection->tableExists("object");
}

// Invalidate the token (for instance if it is deleted)
void DBToken::invalidate()
{
}

// Delete the token.
bool DBToken::clearToken()
{
	if (_connection == NULL) return false;

	std::string tokenDir = _connection->dbdir();
	std::string tokenPath = _connection->dbpath();

	if (!DBObject(_connection).dropTables())
	{
		ERROR_MSG("Failed to drop all tables in the token database at \"%s\"", tokenPath.c_str());
		return false;
	}

	_connection->close();
	delete _connection;
	_connection = NULL;

	// Remove all files from the token directory, even ones not placed there by us.
	Directory dir(tokenDir);
	std::vector<std::string> tokenFiles = dir.getFiles();

	for (std::vector<std::string>::iterator i = tokenFiles.begin(); i != tokenFiles.end(); i++)
	{
		if (!dir.remove(*i))
		{
			ERROR_MSG("Failed to remove \"%s\" from token directory \"%s\"", i->c_str(), tokenDir.c_str());

			return false;
		}
	}

	// Now remove the token directory
	if (!dir.rmdir(""))
	{
		ERROR_MSG("Failed to remove the token directory \"%s\"", tokenDir.c_str());

		return false;
	}

	DEBUG_MSG("Token instance %s was succesfully cleared", tokenDir.c_str());

	return true;
}

// Reset the token
bool DBToken::resetToken(const ByteString& label)
{
	if (_connection == NULL) return false;

	std::string tokenDir = _connection->dbdir();

	// Clean up
	std::set<OSObject*> cleanUp = getObjects();

	for (std::set<OSObject*>::iterator i = cleanUp.begin(); i != cleanUp.end(); i++)
	{
		if (!deleteObject(*i))
		{
			ERROR_MSG("Unable to delete all objects in token database at \"%s\"", _connection->dbpath().c_str());
			return false;
		}
	}

	// Create a DBObject for the established connection to the token object in the database
	DBObject tokenObject(_connection);

	if (!tokenObject.startTransaction(DBObject::ReadWrite))
	{
		ERROR_MSG("Unable to start a transaction for setting the TOKENLABEL in token database at \"%s\"", _connection->dbpath().c_str());
		return false;
	}

	// First find the token object in the database.
	if (!tokenObject.find(DBTOKEN_OBJECT_TOKENINFO))
	{
		ERROR_MSG("Token object not found in token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	if (tokenObject.attributeExists(CKA_OS_USERPIN))
	{
		if (!tokenObject.deleteAttribute(CKA_OS_USERPIN))
		{
			ERROR_MSG("Error while deleting USERPIN in token database at \"%s\"", _connection->dbpath().c_str());
			tokenObject.abortTransaction();
			return false;
		}
	}

	if (!tokenObject.attributeExists(CKA_OS_TOKENFLAGS))
	{
		ERROR_MSG("Error while getting TOKENFLAGS from token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	// Retrieve flags from the database and reset flags related to tries and expiration of the SOPIN.
	CK_ULONG flags = tokenObject.getAttribute(CKA_OS_TOKENFLAGS).getUnsignedLongValue()
					& ~(CKF_USER_PIN_INITIALIZED | CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY | CKF_USER_PIN_LOCKED | CKF_USER_PIN_TO_BE_CHANGED);

	OSAttribute changedTokenFlags(flags);
	if (!tokenObject.setAttribute(CKA_OS_TOKENFLAGS, changedTokenFlags))
	{
		ERROR_MSG("Error while setting TOKENFLAGS in token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	OSAttribute tokenLabel(label);
	if (!tokenObject.setAttribute(CKA_OS_TOKENLABEL, tokenLabel))
	{
		ERROR_MSG("Error while setting TOKENLABEL in token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	if (!tokenObject.commitTransaction())
	{
		ERROR_MSG("Error while committing TOKENLABEL changes to token database at \"%s\"", _connection->dbpath().c_str());
		tokenObject.abortTransaction();
		return false;
	}

	DEBUG_MSG("Token instance %s was succesfully reset", tokenDir.c_str());

	return true;
}
