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

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <cstdio>
#include <map>

// Create an object that can access a record, but don't do anything yet.
DBObject::DBObject(DB::Connection *connection, ObjectStoreToken *token)
	: _mutex(MutexFactory::i()->getMutex()), _connection(connection), _token(token), _objectId(0)
{

}

DBObject::DBObject(DB::Connection *connection, ObjectStoreToken *token, long long objectId)
	: _mutex(MutexFactory::i()->getMutex()), _connection(connection), _token(token), _objectId(objectId)
{
}

// Destructor
DBObject::~DBObject()
{
	for (std::map<CK_ATTRIBUTE_TYPE,OSAttribute*>::iterator it = _attributes.begin(); it!=_attributes.end(); ++it) {
		delete it->second;
		it->second = NULL;
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

	// attribute_blob
	DB::Statement cr_attr_blob = _connection->prepare(
		"create table attribute_blob ("
		"value blob,"
		"type integer,"
		"object_id integer references object(id) on delete cascade,"
		"id integer primary key autoincrement)"
		);
	if (!_connection->execute(cr_attr_blob))
	{
		ERROR_MSG("Failed to create \"attribute_blob\" table");
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

	// attribute_blob
	DB::Statement dr_attr_blob = _connection->prepare("drop table attribute_blob");
	if (!_connection->execute(dr_attr_blob))
	{
		ERROR_MSG("Failed to drop \"attribute_blob\" table");
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

DBObject::AttributeKind DBObject::findAttribute(CK_ATTRIBUTE_TYPE type)
{
	// We currently search all attribute_xxxxx tables for a match on type and object_id.
	// Because it is fixed for predefined types what underlying type an attribute is, we
	// should be able to optimize this once we create a mapping of CK_ATTRIBUTE_TYPE to
	// attribute table in the DB.

	DB::Statement statement;
	DB::Result result;

	// try to find the attribute in the boolean
	statement = _connection->prepare(
		"select value from attribute_boolean where type=%d and object_id=%lld",
		type,
		_objectId);
	if (!statement.isValid())
	{
		return akUnknown;
	}

	result = _connection->perform(statement);
	if (result.isValid())
	{
		return akBoolean;
	}

	// try to find the attribute in the boolean
	statement = _connection->prepare(
		"select value from attribute_integer where type=%d and object_id=%lld",
		type,
		_objectId);
	if (!statement.isValid())
	{
		return akUnknown;
	}

	result = _connection->perform(statement);
	if (result.isValid())
	{
		return akInteger;
	}

	// try to find the attribute in the boolean
	statement = _connection->prepare(
		"select value from attribute_blob where type=%d and object_id=%lld",
		type,
		_objectId);
	if (!statement.isValid())
	{
		return akUnknown;
	}

	result = _connection->perform(statement);
	if (result.isValid())
	{
		return akBinary;
	}

	return akUnknown;
}

// Check if the specified attribute exists
bool DBObject::attributeExists(CK_ATTRIBUTE_TYPE type)
{
	MutexLocker lock(_mutex);

	if (_connection == NULL)
	{
		ERROR_MSG("Object is not connected to the database.");
		return false;
	}
	if (_objectId == 0)
	{
		ERROR_MSG("Cannot access invalid object.");
		return false;
	}

	return findAttribute(type) != akUnknown;
}

// Retrieve the specified attribute
OSAttribute* DBObject::getAttribute(CK_ATTRIBUTE_TYPE type)
{
	MutexLocker lock(_mutex);

	if (_connection == NULL)
	{
		ERROR_MSG("Object is not connected to the database.");
		return false;
	}
	if (_objectId == 0)
	{
		ERROR_MSG("Cannot read from invalid object.");
		return false;
	}

	// try to find the attribute in the boolean attribute table
	DB::Statement statement = _connection->prepare(
		"select value from attribute_boolean where type=%d and object_id=%lld",
		type,
		_objectId);
	if (statement.isValid())
	{
		DB::Result result = _connection->perform(statement);
		if (result.isValid())
		{
			bool value = result.getInt(1) != 0;

			if (_attributes[type] && _attributes[type]->isBooleanAttribute())
				_attributes[type]->setBooleanValue(value);
			else
				_attributes[type] = new OSAttribute(value);

			return _attributes[type];
		}
	}

	// try to find the attribute in the integer attribute table
	statement = _connection->prepare(
		"select value from attribute_integer where type=%d and object_id=%lld",
		type,
		_objectId);
	if (statement.isValid())
	{
		DB::Result result = _connection->perform(statement);
		if (result.isValid())
		{
			unsigned long long value = result.getULongLong(1);
			if (_attributes[type] && _attributes[type]->isUnsignedLongAttribute())
				_attributes[type]->setUnsignedLongValue(value);
			else
				_attributes[type] = new OSAttribute(static_cast<unsigned long>(value));

			return _attributes[type];
		}
	}

	// try to find the attribute in the integer attribute table
	statement = _connection->prepare(
		"select value from attribute_blob where type=%d and object_id=%lld",
		type,
		_objectId);
	if (statement.isValid())
	{
		DB::Result result = _connection->perform(statement);
		if (result.isValid())
		{
			const unsigned char *value = result.getBinary(1);
			size_t size = result.getFieldLength(1);
			if (_attributes[type] && _attributes[type]->isByteStringAttribute())
				_attributes[type]->setByteStringValue(ByteString(value, size));
			else
				_attributes[type] = new OSAttribute(ByteString(value, size));

			return _attributes[type];
		}
	}

	// access integers
	// access binary
	return NULL;
}

CK_ATTRIBUTE_TYPE DBObject::nextAttributeType(CK_ATTRIBUTE_TYPE type)
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
	
	// Fixme, implement for C_CopyObject
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

	AttributeKind ak = findAttribute(type);
	DB::Statement statement;

	// Update and existing attribute...
	switch (ak) {
		case akBoolean:
			// update boolean attribute
			statement = _connection->prepare(
					"update attribute_boolean set value=%d where type=%d and object_id=%lld",
					attribute.getBooleanValue() ? 1 : 0,
					type,
					_objectId);

			if (!_connection->execute(statement))
			{
				ERROR_MSG("Failed to update boolean attribute %d for object %lld",type,_objectId);
				return false;
			}
			*_attributes[type] = attribute;
			return true;

		case akInteger:
			// update integer attribute
			statement = _connection->prepare(
					"update attribute_integer set value=%lld where type=%d and object_id=%lld",
					static_cast<long long>(attribute.getUnsignedLongValue()),
					type,
					_objectId);

			if (!_connection->execute(statement))
			{
				ERROR_MSG("Failed to update integer attribute %d for object %lld",type,_objectId);
				return false;
			}
			*_attributes[type] = attribute;
			return true;


		case akBinary:
			// update binary attribute
			statement = _connection->prepare(
					"update attribute_blob set value=? where type=%d and object_id=%lld",
					type,
					_objectId);

			DB::Bindings(statement).bindBlob(1, attribute.getByteStringValue().const_byte_str(), attribute.getByteStringValue().size(),NULL);

			if (!_connection->execute(statement))
			{
				ERROR_MSG("Failed to update blob attribute %d for object %lld",type,_objectId);
				return false;
			}
			*_attributes[type] = attribute;
			return true;
	}


	// Insert the attribute, because it is currently unknown
	if (attribute.isBooleanAttribute())
	{
		// Could not update it, so we need to insert it.
		statement = _connection->prepare(
					"insert into attribute_boolean (value,type,object_id) values (%d,%d,%lld)",
					attribute.getBooleanValue() ? 1 : 0,
					type,
					_objectId);

		if (!_connection->execute(statement))
		{
			ERROR_MSG("Failed to insert boolean attribute %d for object %lld",type,_objectId);
			return false;
		}
		_attributes[type] = new OSAttribute(attribute);
		return true;
	}

	// Insert the attribute, because it is currently unknown
	if (attribute.isUnsignedLongAttribute())
	{
		// Could not update it, so we need to insert it.
		statement = _connection->prepare(
					"insert into attribute_integer (value,type,object_id) values (%lld,%d,%lld)",
					static_cast<long long>(attribute.getUnsignedLongValue()),
					type,
					_objectId);

		if (!_connection->execute(statement))
		{
			ERROR_MSG("Failed to insert integer attribute %d for object %lld",type,_objectId);
			return false;
		}

		_attributes[type] = new OSAttribute(attribute);
		return true;
	}


	// Insert the attribute, because it is currently unknown
	if (attribute.isByteStringAttribute())
	{
		// Could not update it, so we need to insert it.
		statement = _connection->prepare(
					"insert into attribute_blob (value,type,object_id) values (?,%d,%lld)",
					type,
					_objectId);

		DB::Bindings(statement).bindBlob(1, attribute.getByteStringValue().const_byte_str(), attribute.getByteStringValue().size(),NULL);

		if (!_connection->execute(statement))
		{
			ERROR_MSG("Failed to insert blob attribute %d for object %lld",type,_objectId);
			return false;
		}

		_attributes[type] = new OSAttribute(attribute);
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

	if (_connection->inTransaction())
	{
		return false;
	}

	// Always start a transaction that can be used for both reading and writing.
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

	return _connection->commitTransaction();
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
