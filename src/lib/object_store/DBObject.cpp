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
 DBObject.h

 This class represents object records in a database
 *****************************************************************************/

#include "config.h"
#include "DBObject.h"
#include "OSPathSep.h"
#include "DB.h"
#include "OSAttributes.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <cstdio>
#include <map>

// Create an object that can access a record, but don't do anything yet.
DBObject::DBObject(DB::Connection *connection, ObjectStoreToken *token)
	: _mutex(MutexFactory::i()->getMutex()), _connection(connection), _token(token), _objectId(0), _transaction(NULL)
{

}

DBObject::DBObject(DB::Connection *connection, ObjectStoreToken *token, long long objectId)
	: _mutex(MutexFactory::i()->getMutex()), _connection(connection), _token(token), _objectId(objectId), _transaction(NULL)
{
}

// Destructor
DBObject::~DBObject()
{
	for (std::map<CK_ATTRIBUTE_TYPE,OSAttribute*>::iterator it = _attributes.begin(); it!=_attributes.end(); ++it) {
		delete it->second;
		it->second = NULL;
	}
	if (_transaction)
	{
		for (std::map<CK_ATTRIBUTE_TYPE,OSAttribute*>::iterator it = _transaction->begin(); it!=_transaction->end(); ++it) {
			delete it->second;
			it->second = NULL;
		}
		delete _transaction;
	}
	MutexFactory::i()->recycleMutex(_mutex);
}

void DBObject::dropConnection()
{
	MutexLocker lock(_mutex);

	_connection = NULL;
}

// create tables to support storage of attributes for the DBObject
bool DBObject::createTables()
{
	MutexLocker lock(_mutex);

	if (_connection == NULL)
	{
		ERROR_MSG("Object is not connected to the database.");
		return false;
	}

	// Create the tables inside the database
	DB::Statement cr_object = _connection->prepare("create table object (id integer primary key autoincrement);");
	if (!_connection->execute(cr_object))
	{
		ERROR_MSG("Failed to create \"object\" table");
		return false;
	}

	// attribute_text
	DB::Statement cr_attr_text = _connection->prepare(
		"create table attribute_text ("
		"value text,"
		"type integer,"
		"object_id integer references object(id) on delete cascade,"
		"id integer primary key autoincrement)"
		);
	if (!_connection->execute(cr_attr_text))
	{
		ERROR_MSG("Failed to create \"attribute_text\" table");
		return false;
	}

	// attribute_integer
	DB::Statement cr_attr_integer = _connection->prepare(
		"create table attribute_integer ("
		"value integer,"
		"type integer,"
		"object_id integer references object(id) on delete cascade,"
		"id integer primary key autoincrement)"
		);
	if (!_connection->execute(cr_attr_integer))
	{
		ERROR_MSG("Failed to create \"attribute_integer\" table");
		return false;
	}

	// attribute_binary
	DB::Statement cr_attr_binary = _connection->prepare(
		"create table attribute_binary ("
		"value blob,"
		"type integer,"
		"object_id integer references object(id) on delete cascade,"
		"id integer primary key autoincrement)"
		);
	if (!_connection->execute(cr_attr_binary))
	{
		ERROR_MSG("Failed to create \"attribute_binary\" table");
		return false;
	}

	// attribute_array
	DB::Statement cr_attr_array = _connection->prepare(
		"create table attribute_array ("
		"value blob,"
		"type integer,"
		"object_id integer references object(id) on delete cascade,"
		"id integer primary key autoincrement)"
		);
	if (!_connection->execute(cr_attr_array))
	{
		ERROR_MSG("Failed to create \"attribute_array\" table");
		return false;
	}

	// attribute_boolean
	DB::Statement cr_attr_boolean = _connection->prepare(
		"create table attribute_boolean ("
		"value boolean,"
		"type integer,"
		"object_id integer references object(id) on delete cascade,"
		"id integer primary key autoincrement)"
		);
	if (!_connection->execute(cr_attr_boolean))
	{
		ERROR_MSG("Failed to create \"attribute_boolean\" table");
		return false;
	}

	// attribute_datetime
	DB::Statement cr_attr_datetime = _connection->prepare(
		"create table attribute_datetime ("
		"value datetime,"
		"type integer,"
		"object_id integer references object(id) on delete cascade,"
		"id integer primary key autoincrement)"
		);
	if (!_connection->execute(cr_attr_datetime))
	{
		ERROR_MSG("Failed to create \"attribute_datetime\" table");
		return false;
	}

	// attribute_real
	DB::Statement cr_attr_real = _connection->prepare(
		"create table attribute_real ("
		"value real,"
		"type integer,"
		"object_id integer references object(id) on delete cascade,"
		"id integer primary key autoincrement)"
		);
	if (!_connection->execute(cr_attr_real))
	{
		ERROR_MSG("Failed to create \"attribute_real\" table");
		return false;
	}

	return true;
}

bool DBObject::dropTables()
{
	MutexLocker lock(_mutex);

	if (_connection == NULL)
	{
		ERROR_MSG("Object is not connected to the database.");
		return false;
	}

	// Create the tables inside the database
	DB::Statement dr_object = _connection->prepare("drop table object");
	if (!_connection->execute(dr_object))
	{
		ERROR_MSG("Failed to drop \"object\" table");
		return false;
	}

	// attribute_text
	DB::Statement dr_attr_text = _connection->prepare("drop table attribute_text");
	if (!_connection->execute(dr_attr_text))
	{
		ERROR_MSG("Failed to drop \"attribute_text\" table");
		return false;
	}

	// attribute_integer
	DB::Statement dr_attr_integer = _connection->prepare("drop table attribute_integer");
	if (!_connection->execute(dr_attr_integer))
	{
		ERROR_MSG("Failed to drop \"attribute_integer\" table");
		return false;
	}

	// attribute_binary
	DB::Statement dr_attr_binary = _connection->prepare("drop table attribute_binary");
	if (!_connection->execute(dr_attr_binary))
	{
		ERROR_MSG("Failed to drop \"attribute_binary\" table");
		return false;
	}

	// attribute_array
	DB::Statement dr_attr_array = _connection->prepare("drop table attribute_array");
	if (!_connection->execute(dr_attr_array))
	{
		ERROR_MSG("Failed to drop \"attribute_array\" table");
		return false;
	}

	// attribute_boolean
	DB::Statement dr_attr_boolean = _connection->prepare("drop table attribute_boolean");
	if (!_connection->execute(dr_attr_boolean))
	{
		ERROR_MSG("Failed to drop \"attribute_boolean\" table");
		return false;
	}

	// attribute_datetime
	DB::Statement dr_attr_datetime = _connection->prepare("drop table attribute_datetime");
	if (!_connection->execute(dr_attr_datetime))
	{
		ERROR_MSG("Failed to drop \"attribute_datetime\" table");
		return false;
	}

	// attribute_real
	DB::Statement dr_attr_real = _connection->prepare("drop table attribute_real");
	if (!_connection->execute(dr_attr_real))
	{
		ERROR_MSG("Failed to drop \"attribute_real\" table");
		return false;
	}

	return true;
}

bool DBObject::find(long long objectId)
{
	MutexLocker lock(_mutex);

	if (_connection == NULL)
	{
		ERROR_MSG("Object is not connected to the database.");
		return false;
	}

	if (objectId == 0) {
		ERROR_MSG("Invalid object_id 0 passed to find");
		return false;
	}

	// find the object in the database for the given object_id
	DB::Statement statement = _connection->prepare(
				"select id from object where id=%lld",
				objectId);
	if (!statement.isValid()) {
		ERROR_MSG("Preparing object selection statement failed");
		return false;
	}

	DB::Result result = _connection->perform(statement);
	if (result.getLongLong(1) != objectId) {
		ERROR_MSG("Failed to find object with id %lld",objectId);
		return false;
	}

	_objectId = objectId;
	return true;
}

bool DBObject::insert()
{
	MutexLocker lock(_mutex);

	if (_connection == NULL)
	{
		ERROR_MSG("Object is not connected to the database.");
		return false;
	}

	DB::Statement statement = _connection->prepare("insert into object default values");

	if (!_connection->execute(statement)) {
		ERROR_MSG("Failed to insert a new object");
		return false;
	}

	_objectId = _connection->lastInsertRowId();
	return _objectId != 0;
}

bool DBObject::remove()
{
	MutexLocker lock(_mutex);

	if (_connection == NULL)
	{
		ERROR_MSG("Object is not connected to the database.");
		return false;
	}

	DB::Statement statement = _connection->prepare("delete from object where id=%lld",_objectId);

	if (!_connection->execute(statement)) {
		ERROR_MSG("Failed to remove an existing object");
		return false;
	}

	_objectId = 0;
	return true;
}

long long DBObject::objectId()
{
	MutexLocker lock(_mutex);

	return _objectId;
}

static bool isModifiable(CK_ATTRIBUTE_TYPE type)
{
	switch (type) {
	case CKA_LABEL:
	case CKA_TRUSTED:
	case CKA_ID:
	case CKA_ISSUER:
	case CKA_SERIAL_NUMBER:
	case CKA_START_DATE:
	case CKA_END_DATE:
	case CKA_DERIVE:
	case CKA_SUBJECT:
	case CKA_ENCRYPT:
	case CKA_VERIFY:
	case CKA_VERIFY_RECOVER:
	case CKA_WRAP:
	case CKA_SENSITIVE:
	case CKA_DECRYPT:
	case CKA_SIGN:
	case CKA_SIGN_RECOVER:
	case CKA_UNWRAP:
	case CKA_EXTRACTABLE:
	case CKA_OS_TOKENFLAGS:
	case CKA_OS_SOPIN:
	case CKA_OS_USERPIN:
		return true;
	default:
		return false;
	}
}

enum AttributeKind {
	akUnknown,
	akBoolean,
	akInteger,
	akBinary,
	akAttrMap,
	akMechSet
};

static AttributeKind attributeKind(CK_ATTRIBUTE_TYPE type)
{
	switch (type) {
	case CKA_CLASS: return akInteger;
	case CKA_TOKEN: return akBoolean;
	case CKA_PRIVATE: return akBoolean;
	case CKA_LABEL: return akBinary;
	case CKA_APPLICATION: return akBinary;
	case CKA_VALUE: return akBinary;
	case CKA_OBJECT_ID: return akBinary;
	case CKA_CERTIFICATE_TYPE: return akInteger;
	case CKA_ISSUER: return akBinary;
	case CKA_SERIAL_NUMBER: return akBinary;
	case CKA_AC_ISSUER: return akBinary;
	case CKA_OWNER: return akBinary;
	case CKA_ATTR_TYPES: return akBinary;
	case CKA_TRUSTED: return akBoolean;
	case CKA_CERTIFICATE_CATEGORY: return akInteger;
	case CKA_JAVA_MIDP_SECURITY_DOMAIN: return akInteger;
	case CKA_URL: return akBinary;
	case CKA_HASH_OF_SUBJECT_PUBLIC_KEY: return akBinary;
	case CKA_HASH_OF_ISSUER_PUBLIC_KEY: return akBinary;
	case CKA_NAME_HASH_ALGORITHM: return akInteger;
	case CKA_CHECK_VALUE: return akBinary;
	case CKA_KEY_TYPE: return akInteger;
	case CKA_SUBJECT: return akBinary;
	case CKA_ID: return akBinary;
	case CKA_SENSITIVE: return akBoolean;
	case CKA_ENCRYPT: return akBoolean;
	case CKA_DECRYPT: return akBoolean;
	case CKA_WRAP: return akBoolean;
	case CKA_UNWRAP: return akBoolean;
	case CKA_SIGN: return akBoolean;
	case CKA_SIGN_RECOVER: return akBoolean;
	case CKA_VERIFY: return akBoolean;
	case CKA_VERIFY_RECOVER: return akBoolean;
	case CKA_DERIVE: return akBoolean;
	case CKA_START_DATE: return akBinary;
	case CKA_END_DATE: return akBinary;
	case CKA_MODULUS: return akBinary;
	case CKA_MODULUS_BITS: return akInteger;
	case CKA_PUBLIC_EXPONENT: return akBinary;
	case CKA_PRIVATE_EXPONENT: return akBinary;
	case CKA_PRIME_1: return akBinary;
	case CKA_PRIME_2: return akBinary;
	case CKA_EXPONENT_1: return akBinary;
	case CKA_EXPONENT_2: return akBinary;
	case CKA_COEFFICIENT: return akBinary;
	case CKA_PRIME: return akBinary;
	case CKA_SUBPRIME: return akBinary;
	case CKA_BASE: return akBinary;
	case CKA_PRIME_BITS: return akInteger;
	case CKA_SUB_PRIME_BITS: return akInteger;
	case CKA_VALUE_BITS: return akInteger;
	case CKA_VALUE_LEN: return akInteger;
	case CKA_EXTRACTABLE: return akBoolean;
	case CKA_LOCAL: return akBoolean;
	case CKA_NEVER_EXTRACTABLE: return akBoolean;
	case CKA_ALWAYS_SENSITIVE: return akBoolean;
	case CKA_KEY_GEN_MECHANISM: return akInteger;
	case CKA_MODIFIABLE: return akBoolean;
	case CKA_COPYABLE: return akBoolean;
	case CKA_ECDSA_PARAMS: return akBinary;
	case CKA_EC_POINT: return akBinary;
	case CKA_SECONDARY_AUTH: return akBoolean;
	case CKA_AUTH_PIN_FLAGS: return akInteger;
	case CKA_ALWAYS_AUTHENTICATE: return akBoolean;
	case CKA_WRAP_WITH_TRUSTED: return akBoolean;
/*
	case CKA_OTP_FORMAT:
	case CKA_OTP_LENGTH:
	case CKA_OTP_TIME_INTERVAL:
	case CKA_OTP_USER_FRIENDLY_MODE:
	case CKA_OTP_CHALLENGE_REQUIREMENT:
	case CKA_OTP_TIME_REQUIREMENT:
	case CKA_OTP_COUNTER_REQUIREMENT:
	case CKA_OTP_PIN_REQUIREMENT:
	case CKA_OTP_COUNTER:
	case CKA_OTP_TIME:
	case CKA_OTP_USER_IDENTIFIER:
	case CKA_OTP_SERVICE_IDENTIFIER:
	case CKA_OTP_SERVICE_LOGO:
	case CKA_OTP_SERVICE_LOGO_TYPE:
*/
	case CKA_GOSTR3410_PARAMS: return akBinary;
	case CKA_GOSTR3411_PARAMS: return akBinary;
	case CKA_GOST28147_PARAMS: return akBinary;
/*
	case CKA_HW_FEATURE_TYPE:
	case CKA_RESET_ON_INIT:
	case CKA_HAS_RESET:
	case CKA_PIXEL_X:
	case CKA_PIXEL_Y:
	case CKA_RESOLUTION:
	case CKA_CHAR_ROWS:
	case CKA_CHAR_COLUMNS:
	case CKA_COLOR:
	case CKA_BITS_PER_PIXEL:
	case CKA_CHAR_SETS:
	case CKA_ENCODING_METHODS:
	case CKA_MIME_TYPES:
	case CKA_MECHANISM_TYPE:
	case CKA_REQUIRED_CMS_ATTRIBUTES:
	case CKA_DEFAULT_CMS_ATTRIBUTES:
	case CKA_SUPPORTED_CMS_ATTRIBUTES:
*/
	case CKA_WRAP_TEMPLATE: return akAttrMap;
	case CKA_UNWRAP_TEMPLATE: return akAttrMap;
	case CKA_DERIVE_TEMPLATE: return akAttrMap;
	case CKA_ALLOWED_MECHANISMS: return akMechSet;

	case CKA_OS_TOKENLABEL: return akBinary;
	case CKA_OS_TOKENSERIAL: return akBinary;
	case CKA_OS_TOKENFLAGS: return akInteger;
	case CKA_OS_SOPIN: return akBinary;
	case CKA_OS_USERPIN: return akBinary;

	default: return akUnknown;
	}
}

static bool decodeMechanismTypeSet(std::set<CK_MECHANISM_TYPE>& set, const unsigned char *binary, size_t size)
{
	for (size_t pos = 0; pos < size; )
	{
		// finished?
		if (pos == size) break;

		CK_MECHANISM_TYPE mechType;
		if (pos + sizeof(mechType) > size)
		{
			ERROR_MSG("mechanism type set overrun");
			return false;
		}

		memcpy(&mechType, binary + pos, sizeof(mechType));
		pos += sizeof(mechType);

		set.insert(mechType);
    }

	return true;
}

static void encodeMechanismTypeSet(ByteString& value, const std::set<CK_MECHANISM_TYPE>& set)
{
	for (std::set<CK_MECHANISM_TYPE>::const_iterator i = set.begin(); i != set.end(); ++i)
	{
		CK_MECHANISM_TYPE mechType = *i;
		value += ByteString((unsigned char *) &mechType, sizeof(mechType));
	}
}

static bool decodeAttributeMap(std::map<CK_ATTRIBUTE_TYPE,OSAttribute>& map, const unsigned char *binary, size_t size)
{
	for (size_t pos = 0; pos < size; )
	{
		// finished?
		if (pos == size) break;

		CK_ATTRIBUTE_TYPE attrType;
		if (pos + sizeof(attrType) > size)
		{
			goto overrun;
		}
		memcpy(&attrType, binary + pos, sizeof(attrType));
		pos += sizeof(attrType);

		AttributeKind attrKind;
		if (pos + sizeof(AttributeKind) > size)
		{
			goto overrun;
		}
		memcpy(&attrKind, binary + pos, sizeof(attrKind));
		pos += sizeof(attrKind);

		// Verify using attributeKind()?

		switch (attrKind)
		{
			case akBoolean:
			{
				bool value;
				if (pos + sizeof(value) > size)
				{
					goto overrun;
				}
				memcpy(&value, binary + pos, sizeof(value));
				pos += sizeof(value);

				map.insert(std::pair<CK_ATTRIBUTE_TYPE,OSAttribute> (attrType, value));
			}
			break;

			case akInteger:
			{
				unsigned long value;
				if (pos + sizeof(value) > size)
				{
					goto overrun;
				}
				memcpy(&value, binary + pos, sizeof(value));
				pos += sizeof(value);

				map.insert(std::pair<CK_ATTRIBUTE_TYPE,OSAttribute> (attrType, value));
			}
			break;

			case akBinary:
			{
				ByteString value;
				unsigned long len;
				if (pos + sizeof(len) > size)
				{
					goto overrun;
				}
				memcpy(&len, binary + pos, sizeof(len));
				pos += sizeof(len);

				if (pos + len > size)
				{
					goto overrun;
				}
				value.resize(len);
				memcpy(&value[0], binary + pos, len);
				pos += len;

				map.insert(std::pair<CK_ATTRIBUTE_TYPE,OSAttribute> (attrType, value));
			}
			break;

			case akMechSet:
			{
				unsigned long len;
				if (pos + sizeof(len) > size)
				{
					goto overrun;
				}
				memcpy(&len, binary + pos, sizeof(len));
				pos += sizeof(len);

				if (pos + len > size)
				{
					goto overrun;
				}

				std::set<CK_MECHANISM_TYPE> value;
				if (!decodeMechanismTypeSet(value, binary + pos, len)) {
					return false;
				}
				pos += len;

				map.insert(std::pair<CK_ATTRIBUTE_TYPE,OSAttribute> (attrType, value));
			}
			break;

			default:
			ERROR_MSG("unsupported attribute kind in attribute map");

			return false;
		}
	}

	return true;

overrun:
	ERROR_MSG("attribute map template overrun");

	return false;
}

static bool encodeAttributeMap(ByteString& value, const std::map<CK_ATTRIBUTE_TYPE,OSAttribute>& attributes)
{
	for (std::map<CK_ATTRIBUTE_TYPE,OSAttribute>::const_iterator i = attributes.begin(); i != attributes.end(); ++i)
	{
		CK_ATTRIBUTE_TYPE attrType = i->first;
		value += ByteString((unsigned char*) &attrType, sizeof(attrType));

		OSAttribute attr = i->second;
		if (attr.isBooleanAttribute())
		{
			AttributeKind attrKind = akBoolean;
			value += ByteString((unsigned char*) &attrKind, sizeof(attrKind));

			bool val = attr.getBooleanValue();
			value += ByteString((unsigned char*) &val, sizeof(val));
		}
		else if (attr.isUnsignedLongAttribute())
		{
			AttributeKind attrKind = akInteger;
			value += ByteString((unsigned char*) &attrKind, sizeof(attrKind));

			unsigned long val = attr.getUnsignedLongValue();
			value += ByteString((unsigned char*) &val, sizeof(val));
		}
		else if (attr.isByteStringAttribute())
		{
			AttributeKind attrKind = akBinary;
			value += ByteString((unsigned char*) &attrKind, sizeof(attrKind));

			ByteString val = attr.getByteStringValue();
			unsigned long len = val.size();
			value += ByteString((unsigned char*) &len, sizeof(len));
			value += val;
		}
		else if (attr.isMechanismTypeSetAttribute())
		{
			AttributeKind attrKind = akMechSet;
			value += ByteString((unsigned char*) &attrKind, sizeof(attrKind));

			ByteString val;
			encodeMechanismTypeSet(val, attr.getMechanismTypeSetValue());

			unsigned long len = val.size();
			value += ByteString((unsigned char*) &len, sizeof(len));
			value += val;
		}
		else
		{
			ERROR_MSG("unsupported attribute kind for attribute map");

			return false;
		}
	}

	return true;
}

OSAttribute *DBObject::accessAttribute(CK_ATTRIBUTE_TYPE type)
{
	switch (attributeKind(type))
	{
		case akUnknown:
			return NULL;
		case akBoolean:
		{
			// try to find the attribute in the boolean attribute table
			DB::Statement statement = _connection->prepare(
				"select value from attribute_boolean where type=%lu and object_id=%lld",
				type,
				_objectId);
			if (!statement.isValid())
			{
				return NULL;
			}
			DB::Result result = _connection->perform(statement);
			if (!result.isValid())
			{
				return NULL;
			}
			// Store the attribute in the transaction when it is active.
			std::map<CK_ATTRIBUTE_TYPE,OSAttribute*> *attrs = &_attributes;
			if (_transaction)
				attrs = _transaction;

			bool value = result.getInt(1) != 0;
			std::map<CK_ATTRIBUTE_TYPE,OSAttribute*>::iterator it =	 attrs->find(type);
			OSAttribute *attr;
			if (it != attrs->end())
			{
				if (it->second != NULL)
				{
					delete it->second;
				}

				it->second = new OSAttribute(value);
				attr = it->second;
			}
			else
			{
				attr = new OSAttribute(value);
				(*attrs)[type] = attr;
			}
			return attr;
		}
		case akInteger:
		{
			// try to find the attribute in the integer attribute table
			DB::Statement statement = _connection->prepare(
				"select value from attribute_integer where type=%lu and object_id=%lld",
				type,
				_objectId);
			if (!statement.isValid())
			{
				return NULL;
			}
			DB::Result result = _connection->perform(statement);
			if (!result.isValid())
			{
				return NULL;
			}
			// Store the attribute in the transaction when it is active.
			std::map<CK_ATTRIBUTE_TYPE,OSAttribute*> *attrs = &_attributes;
			if (_transaction)
				attrs = _transaction;

			unsigned long value = result.getULongLong(1);
			std::map<CK_ATTRIBUTE_TYPE,OSAttribute*>::iterator it =	 attrs->find(type);
			OSAttribute *attr;
			if (it != attrs->end())
			{
				if (it->second != NULL)
				{
					delete it->second;
				}

				it->second = new OSAttribute(value);
				attr = it->second;
			}
			else
			{
				attr = new OSAttribute(value);
				(*attrs)[type] = attr;
			}
			return attr;
		}
		case akBinary:
		{
			// try to find the attribute in the binary attribute table
			DB::Statement statement = _connection->prepare(
				"select value from attribute_binary where type=%lu and object_id=%lld",
				type,
				_objectId);
			if (!statement.isValid())
			{
				return NULL;
			}
			DB::Result result = _connection->perform(statement);
			if (!result.isValid())
			{
				return NULL;
			}
			// Store the attribute in the transaction when it is active.
			std::map<CK_ATTRIBUTE_TYPE,OSAttribute*> *attrs = &_attributes;
			if (_transaction)
				attrs = _transaction;

			const unsigned char *value = result.getBinary(1);
			size_t size = result.getFieldLength(1);
			std::map<CK_ATTRIBUTE_TYPE,OSAttribute*>::iterator it =	 attrs->find(type);
			OSAttribute *attr;
			if (it != attrs->end())
			{
				if (it->second != NULL)
				{
					delete it->second;
				}

				it->second = new OSAttribute(ByteString(value,size));
				attr = it->second;
			}
			else
			{
				attr = new OSAttribute(ByteString(value,size));
				(*attrs)[type] = attr;
				return attr;
			}
			return attr;
		}
		case akMechSet:
		{
			// try to find the attribute in the binary attribute table
			DB::Statement statement = _connection->prepare(
					"select value from attribute_binary where type=%lu and object_id=%lld",
					type,
					_objectId);
			if (!statement.isValid())
			{
				return NULL;
			}
			DB::Result result = _connection->perform(statement);
			if (!result.isValid())
			{
				return NULL;
			}
			// Store the attribute in the transaction when it is active.
			std::map<CK_ATTRIBUTE_TYPE,OSAttribute*> *attrs = &_attributes;
			if (_transaction)
				attrs = _transaction;

			const unsigned char *value = result.getBinary(1);
			size_t size = result.getFieldLength(1);

			std::set<CK_MECHANISM_TYPE> set;
			if (!decodeMechanismTypeSet(set, value, size))
			{
				return NULL;
			}

			OSAttribute *attr;
			std::map<CK_ATTRIBUTE_TYPE,OSAttribute*>::iterator it =	 attrs->find(type);
			if (it != attrs->end())
			{
				if (it->second != NULL)
				{
					delete it->second;
				}

				it->second = new OSAttribute(set);
				attr = it->second;
			}
			else
			{
				attr = new OSAttribute(set);
				(*attrs)[type] = attr;
				return attr;
			}
			return attr;
		}
		case akAttrMap:
		{
			// try to find the attribute in the array attribute table
			DB::Statement statement = _connection->prepare(
				"select value from attribute_array where type=%lu and object_id=%lld",
				type,
				_objectId);
			if (!statement.isValid())
			{
				return NULL;
			}
			DB::Result result = _connection->perform(statement);
			if (!result.isValid())
			{
				return NULL;
			}
			// Store the attribute in the transaction when it is active.
			std::map<CK_ATTRIBUTE_TYPE,OSAttribute*> *attrs = &_attributes;
			if (_transaction)
				attrs = _transaction;

			const unsigned char *binary = result.getBinary(1);
			size_t size = result.getFieldLength(1);
			std::map<CK_ATTRIBUTE_TYPE,OSAttribute*>::iterator it =	 attrs->find(type);
			OSAttribute *attr;
			if (it != attrs->end())
			{
				std::map<CK_ATTRIBUTE_TYPE,OSAttribute> value;
				if (!decodeAttributeMap(value,binary,size))
				{
					return NULL;
				}

				if (it->second != NULL)
				{
					delete it->second;
				}

				it->second = new OSAttribute(value);
				attr = it->second;
			}
			else
			{
				std::map<CK_ATTRIBUTE_TYPE,OSAttribute> value;
				if (!decodeAttributeMap(value,binary,size))
				{
					return NULL;
				}
				attr = new OSAttribute(value);
				(*attrs)[type] = attr;
				return attr;
			}
			return attr;
		}
	}

	return NULL;
}

// Retrieve the specified attribute for internal use
// Calling function must lock the mutex
OSAttribute* DBObject::getAttributeDB(CK_ATTRIBUTE_TYPE type)
{
	if (_connection == NULL)
	{
		ERROR_MSG("Object is not connected to the database.");
		return NULL;
	}

	if (_objectId == 0)
	{
		ERROR_MSG("Cannot read from invalid object.");
		return NULL;
	}

	// If a transaction is in progress, we can just return the attribute from the transaction.
	if (_transaction)
	{
		std::map<CK_ATTRIBUTE_TYPE,OSAttribute*>::iterator it =	 _transaction->find(type);
		if (it != _transaction->end())
			return it->second;
	}

	// If the attribute exists and is non-modifiable then return a previously retrieved attribute value.
	if (!isModifiable(type))
	{
		std::map<CK_ATTRIBUTE_TYPE,OSAttribute*>::iterator it =	 _attributes.find(type);
		if (it != _attributes.end())
		{
			return it->second;
		}
	}

	return accessAttribute(type);
}

// Check if the specified attribute exists
bool DBObject::attributeExists(CK_ATTRIBUTE_TYPE type)
{
	MutexLocker lock(_mutex);

	return getAttributeDB(type) != NULL;
}

// Retrieve the specified attribute
OSAttribute DBObject::getAttribute(CK_ATTRIBUTE_TYPE type)
{
	MutexLocker lock(_mutex);

	OSAttribute* attr = getAttributeDB(type);
	if (attr == NULL) return OSAttribute((unsigned long)0);

	return *attr;
}

bool DBObject::getBooleanValue(CK_ATTRIBUTE_TYPE type, bool val)
{
	MutexLocker lock(_mutex);

	OSAttribute* attr = getAttributeDB(type);
	if (attr == NULL) return val;

	if (attr->isBooleanAttribute())
	{
		return attr->getBooleanValue();
	}
	else
	{
		ERROR_MSG("The attribute is not a boolean: 0x%08X", type);
		return val;
	}
}

unsigned long DBObject::getUnsignedLongValue(CK_ATTRIBUTE_TYPE type, unsigned long val)
{
	MutexLocker lock(_mutex);

	OSAttribute* attr = getAttributeDB(type);
	if (attr == NULL) return val;

	if (attr->isUnsignedLongAttribute())
	{
		return attr->getUnsignedLongValue();
	}
	else
	{
		ERROR_MSG("The attribute is not an unsigned long: 0x%08X", type);
		return val;
	}
}

ByteString DBObject::getByteStringValue(CK_ATTRIBUTE_TYPE type)
{
	MutexLocker lock(_mutex);

	ByteString val;

	OSAttribute* attr = getAttributeDB(type);
	if (attr == NULL) return val;

	if (attr->isByteStringAttribute())
	{
		return attr->getByteStringValue();
	}
	else
	{
		ERROR_MSG("The attribute is not a byte string: 0x%08X", type);
		return val;
	}
}

CK_ATTRIBUTE_TYPE DBObject::nextAttributeType(CK_ATTRIBUTE_TYPE)
{
	MutexLocker lock(_mutex);

	if (_connection == NULL)
	{
		ERROR_MSG("Object is not connected to the database.");
		return false;
	}
	if (_objectId == 0)
	{
		ERROR_MSG("Cannot get next attribute for invalid object.");
		return false;
	}

	// FIXME: implement for C_CopyObject
	return CKA_CLASS;
}

// Set the specified attribute
bool DBObject::setAttribute(CK_ATTRIBUTE_TYPE type, const OSAttribute& attribute)
{
	MutexLocker lock(_mutex);

	if (_connection == NULL)
	{
		ERROR_MSG("Object is not connected to the database.");
		return false;
	}
	if (_objectId == 0)
	{
		ERROR_MSG("Cannot update invalid object.");
		return false;
	}

	// Retrieve and existing attribute if it exists or NULL if it doesn't
	OSAttribute *attr = getAttributeDB(type);

	// Update an existing attribute...
	if (attr)
	{
		DB::Statement statement;
		if (attr->isBooleanAttribute())
		{
			// update boolean attribute
			statement = _connection->prepare(
					"update attribute_boolean set value=%d where type=%lu and object_id=%lld",
					attribute.getBooleanValue() ? 1 : 0,
					type,
					_objectId);
		}
		else if (attr->isUnsignedLongAttribute())
		{
			// update integer attribute
			statement = _connection->prepare(
					"update attribute_integer set value=%lld where type=%lu and object_id=%lld",
					static_cast<long long>(attribute.getUnsignedLongValue()),
					type,
					_objectId);
		}
		else if (attr->isByteStringAttribute())
		{
			// update binary attribute
			statement = _connection->prepare(
					"update attribute_binary set value=? where type=%lu and object_id=%lld",
					type,
					_objectId);
			DB::Bindings(statement).bindBlob(1, attribute.getByteStringValue().const_byte_str(), attribute.getByteStringValue().size(), SQLITE_STATIC);
		}
		else if (attr->isMechanismTypeSetAttribute())
		{
			// update binary attribute
			ByteString value;
			encodeMechanismTypeSet(value, attribute.getMechanismTypeSetValue());

			statement = _connection->prepare(
					"update attribute_binary set value=? where type=%lu and object_id=%lld",
					type,
					_objectId);
			DB::Bindings(statement).bindBlob(1, value.const_byte_str(), value.size(), SQLITE_TRANSIENT);
		}
		else if (attr->isAttributeMapAttribute())
		{
			// update attribute map attribute
			ByteString value;
			if (!encodeAttributeMap(value, attribute.getAttributeMapValue()))
			{
				return false;
			}

			statement = _connection->prepare(
					"update attribute_array set value=? where type=%lu and object_id=%lld",
					type,
					_objectId);
			DB::Bindings(statement).bindBlob(1, value.const_byte_str(), value.size(), SQLITE_TRANSIENT);
		}

		// Statement is valid when a prepared statement has been attached to it.
		if (statement.isValid())
		{
			if (!_connection->execute(statement))
			{
				ERROR_MSG("Failed to update attribute %lu for object %lld",type,_objectId);
				return false;
			}

			if (_transaction)
			{
				std::map<CK_ATTRIBUTE_TYPE,OSAttribute*>::iterator it =	 _transaction->find(type);
				if (it != _transaction->end())
					*it->second = attribute;
				else
					(*_transaction)[type] = new OSAttribute(attribute);
			} else
				*attr = attribute;
			return true;
		}
	}

	DB::Statement statement;

	// Insert the attribute, because it is currently unknown
	if (attribute.isBooleanAttribute())
	{
		// Could not update it, so we need to insert it.
		statement = _connection->prepare(
					"insert into attribute_boolean (value,type,object_id) values (%d,%lu,%lld)",
					attribute.getBooleanValue() ? 1 : 0,
					type,
					_objectId);

	}
	else if (attribute.isUnsignedLongAttribute())
	{
		// Could not update it, so we need to insert it.
		statement = _connection->prepare(
					"insert into attribute_integer (value,type,object_id) values (%lld,%lu,%lld)",
					static_cast<long long>(attribute.getUnsignedLongValue()),
					type,
					_objectId);
	}
	else if (attribute.isByteStringAttribute())
	{
		// Could not update it, so we need to insert it.
		statement = _connection->prepare(
					"insert into attribute_binary (value,type,object_id) values (?,%lu,%lld)",
					type,
					_objectId);

		DB::Bindings(statement).bindBlob(1, attribute.getByteStringValue().const_byte_str(), attribute.getByteStringValue().size(), SQLITE_STATIC);
	}
	else if (attribute.isMechanismTypeSetAttribute())
	{
		// Could not update it, so we need to insert it.
		ByteString value;
		encodeMechanismTypeSet(value, attribute.getMechanismTypeSetValue());

		statement = _connection->prepare(
				"insert into attribute_binary (value,type,object_id) values (?,%lu,%lld)",
				type,
				_objectId);
		DB::Bindings(statement).bindBlob(1, value.const_byte_str(), value.size(), SQLITE_TRANSIENT);
	}
	else if (attribute.isAttributeMapAttribute())
	{
		// Could not update it, so we need to insert it.
		ByteString value;
		if (!encodeAttributeMap(value, attribute.getAttributeMapValue()))
		{
			return false;
		}

		statement = _connection->prepare(
				"insert into attribute_array (value,type,object_id) values (?,%lu,%lld)",
				type,
				_objectId);
		DB::Bindings(statement).bindBlob(1, value.const_byte_str(), value.size(), SQLITE_TRANSIENT);
	}

	// Statement is valid when a prepared statement has been attached to it.
	if (statement.isValid())
	{
		if (!_connection->execute(statement))
		{
			ERROR_MSG("Failed to insert attribute %lu for object %lld",type,_objectId);
			return false;
		}

		if (_transaction)
			(*_transaction)[type] = new OSAttribute(attribute);
		else
			_attributes[type] = new OSAttribute(attribute);
		return true;
	}

	return false;
}

// Set the specified attribute
bool DBObject::deleteAttribute(CK_ATTRIBUTE_TYPE type)
{
	MutexLocker lock(_mutex);

	if (_connection == NULL)
	{
		ERROR_MSG("Object is not connected to the database.");
		return false;
	}
	if (_objectId == 0)
	{
		ERROR_MSG("Cannot update invalid object.");
		return false;
	}

	// Retrieve and existing attribute if it exists or NULL if it doesn't
	OSAttribute *attr = getAttributeDB(type);
	if (attr == NULL)
	{
		ERROR_MSG("Cannot delete an attribute that doesn't exist.");
		return false;
	}

	DB::Statement statement;
	if (attr->isBooleanAttribute())
	{
		// delete boolean attribute
		statement = _connection->prepare(
				"delete from attribute_boolean where type=%lu and object_id=%lld",
				type,
				_objectId);
	}
	else if (attr->isUnsignedLongAttribute())
	{
		// delete integer attribute
		statement = _connection->prepare(
				"delete from attribute_integer where type=%lu and object_id=%lld",
				type,
				_objectId);
	}
	else if (attr->isByteStringAttribute() || attr -> isMechanismTypeSetAttribute())
	{
		// delete binary attribute
		statement = _connection->prepare(
				"delete from attribute_binary where type=%lu and object_id=%lld",
				type,
				_objectId);
	}
	else if (attr->isAttributeMapAttribute())
	{
		// delete attribute map attribute
		statement = _connection->prepare(
				"delete from attribute_array where type=%lu and object_id=%lld",
				type,
				_objectId);
	}

	// Statement is valid when a prepared statement has been attached to it.
	if (statement.isValid())
	{
		if (!_connection->execute(statement))
		{
			ERROR_MSG("Failed to delete attribute %lu for object %lld",type,_objectId);
			return false;
		}

		if (_transaction)
		{
			std::map<CK_ATTRIBUTE_TYPE,OSAttribute*>::iterator it =	 _transaction->find(type);
			if (it != _transaction->end())
			{
				delete it->second;
				it->second = NULL;
			}
		}

		return true;
	}

	return false;
}

// The validity state of the object
bool DBObject::isValid()
{
	MutexLocker lock(_mutex);

	return _objectId != 0 && _connection != NULL;
}

// Start an attribute set transaction; this method is used when - for
// example - a key is generated and all its attributes need to be
// persisted in one go.
//
// N.B.: Starting a transaction locks the object!
bool DBObject::startTransaction(Access access)
{
	MutexLocker lock(_mutex);

	if (_connection == NULL)
	{
		ERROR_MSG("Object is not connected to the database.");
		return false;
	}

	if (_transaction)
	{
		ERROR_MSG("Transaction is already active.");
		return false;
	}

	_transaction = new std::map<CK_ATTRIBUTE_TYPE,OSAttribute*>;
	if (_transaction == NULL)
	{
		ERROR_MSG("Not enough memory to start transaction.");
		return false;
	}

	if (_connection->inTransaction())
	{
		ERROR_MSG("Transaction in database is already active.");
		return false;
	}

	// Ask the connection to start the transaction.
	if (access == ReadWrite)
		return _connection->beginTransactionRW();
	else
		return _connection->beginTransactionRO();
}

// Commit an attribute transaction
bool DBObject::commitTransaction()
{
	MutexLocker lock(_mutex);

	if (_connection == NULL)
	{
		ERROR_MSG("Object is not connected to the database.");
		return false;
	}

	if (_transaction == NULL)
	{
		ERROR_MSG("No transaction active.");
		return false;
	}

	if (!_connection->commitTransaction())
	{
		return false;
	}

	// Copy the values from the internally stored transaction to the _attributes field.
	for (std::map<CK_ATTRIBUTE_TYPE,OSAttribute*>::iterator it = _transaction->begin(); it!=_transaction->end(); ++it) {
		std::map<CK_ATTRIBUTE_TYPE,OSAttribute*>::iterator attr_it = _attributes.find(it->first);
		if (attr_it == _attributes.end())
		{
			_attributes[it->first] = it->second;
		}
		else
		{
			*attr_it->second = *it->second;
			delete it->second;
		}
		it->second = NULL;
	}
	delete _transaction;
	_transaction = NULL;
	return true;
}

// Abort an attribute transaction; loads back the previous version of the object from disk
bool DBObject::abortTransaction()
{
	MutexLocker lock(_mutex);

	if (_connection == NULL)
	{
		ERROR_MSG("Object is not connected to the database.");
		return false;
	}

	// Forget the atributes that were set during the transaction.
	if (_transaction)
	{
		for (std::map<CK_ATTRIBUTE_TYPE,OSAttribute*>::iterator it = _transaction->begin(); it!=_transaction->end(); ++it) {
			delete it->second;
			it->second = NULL;
		}
		delete _transaction;
		_transaction = NULL;
	}

	return _connection->rollbackTransaction();
}

// Destroy the object; WARNING: pointers to the object become invalid after this call
bool DBObject::destroyObject()
{
	// NOTE: Do not lock _mutex, because _token will call us back and cause a deadlock.
	// There is no need to lock anyway as _token is a non-mutable pointer, so no race
	// conditions possible.

	if (_token == NULL)
	{
		ERROR_MSG("Cannot destroy an object that is not associated with a token");
		return false;
	}

	return _token->deleteObject(this);
}
