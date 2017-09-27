/*
 * Copyright (c) 2013 .SE (The Internet Infrastructure Foundation)
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
 softhsm2-dump-db.cpp

 This program can be used for dumping SoftHSM v2 database.
 *****************************************************************************/

#include <config.h>

#include <sched.h>
#include <sqlite3.h>
#include <string.h>

#include "common.h"

// Attribute types in database arrays
enum AttributeKind
{
	akUnknown,
	akBoolean,
	akInteger,
	akBinary,
	akArray
};

// Attribute specialization
typedef AttributeTK<CK_ATTRIBUTE_TYPE, AttributeKind, unsigned long> Attribute;

template<>
bool Attribute::isBoolean() const
{
	return kind == akBoolean;
}

template<>
bool Attribute::isInteger() const
{
	return kind == akInteger;
}

template<>
bool Attribute::isBinary() const
{
	return kind == akBinary;
}

template<>
bool Attribute::isMechSet() const
{
	// Mechanism sets are stored as binary in the database
	return false;
}

template<>
void Attribute::dumpType() const
{
	if (sizeof(type) == 4)
	{
		dumpU32((uint32_t)type, true);
	}
	else
	{
		dumpULong(type, true);
	}
}

template<>
void Attribute::dumpKind() const
{
	dumpU32((uint32_t) kind, true);
}

template<>
void Attribute::dumpBoolValue() const
{
	dumpBool1(boolValue, true);
}

template<>
void Attribute::dumpULongValue(unsigned long value) const
{
	if (sizeof(unsigned long) == 4)
	{
		dumpU32(value, true);
	}
	else
	{
		dumpULong(value, true);
	}
}

// dumpArray specialization
typedef std::vector<Attribute> va_type;

void dumpArray(const va_type& value)
{
	for (va_type::const_iterator attr = value.begin(); attr != value.end(); ++attr)
		attr->dump();
}

// Get a boolean (in fact unsigned 8 bit long) value
bool getBool(sqlite3* db, long long oid, long long id, uint64_t& type, uint8_t& value)
{
	int rv;
	sqlite3_stmt* sql = NULL;
	std::string command = "select type,value from attribute_boolean where object_id=? and id=?;";

	value = 0;

	rv = sqlite3_prepare_v2(db, command.c_str(), -1, &sql, NULL);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr,
			"can't find boolean attribute id=%lld object=%lld: %d(%s)\n",
			id, oid, rv, sqlite3_errmsg(db));
		sqlite3_finalize(sql);
		return false;
	}
	rv = sqlite3_bind_int64(sql, 1, oid);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't bind the object id: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sql);
		return false;
	}
	sqlite3_bind_int64(sql, 2, id);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't bind the attribute id: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sql);
		return false;
	}
	while ((rv = sqlite3_step(sql)) == SQLITE_BUSY)
	{
		sched_yield();
	}
	if (rv != SQLITE_ROW)
	{
		fprintf(stderr,
			"can't read boolean attribute id=%lld object=%lld: %d(%s)\n",
			id, oid, rv, sqlite3_errmsg(db));
		sqlite3_finalize(sql);
		return false;
	}
	type = sqlite3_column_int64(sql, 0);
	value = sqlite3_column_int(sql, 1);
	sqlite3_finalize(sql);

	return true;
}

// Get an unsigned 64 bit long value
bool getULong(sqlite3* db, long long oid, long long id, uint64_t& type, uint64_t& value)
{
	int rv;
	sqlite3_stmt* sql = NULL;
	std::string command = "select type,value from attribute_integer where object_id=? and id=?;";

	value = 0ULL;

	rv = sqlite3_prepare_v2(db, command.c_str(), -1, &sql, NULL);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr,
			"can't find integer attribute id=%lld object=%lld: %d(%s)\n",
			id, oid, rv, sqlite3_errmsg(db));
		sqlite3_finalize(sql);
		return false;
	}
	rv = sqlite3_bind_int64(sql, 1, oid);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't bind the object id: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sql);
		return false;
	}
	sqlite3_bind_int64(sql, 2, id);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't bind the attribute id: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sql);
		return false;
	}
	while ((rv = sqlite3_step(sql)) == SQLITE_BUSY)
	{
		sched_yield();
	}
	if (rv != SQLITE_ROW)
	{
		fprintf(stderr,
			"can't read integer attribute id=%lld object=%lld: %d(%s)\n",
			id, oid, rv, sqlite3_errmsg(db));
		sqlite3_finalize(sql);
		return false;
	}
	type = sqlite3_column_int64(sql, 0);
	value = sqlite3_column_int64(sql, 1);
	sqlite3_finalize(sql);

	return true;
}

// Get a byte string (aka uint8_t vector) value
bool getBytes(sqlite3* db, long long oid, long long id, uint64_t& type, std::vector<uint8_t>& value)
{
	int rv;
	sqlite3_stmt* sql = NULL;
	std::string command = "select type,value from attribute_binary where object_id=? and id=?;";
	size_t len;
	const uint8_t* val;

	value.clear();

	rv = sqlite3_prepare_v2(db, command.c_str(), -1, &sql, NULL);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr,
			"can't find binary attribute id=%lld object=%lld: %d(%s)\n",
			id, oid, rv, sqlite3_errmsg(db));
		sqlite3_finalize(sql);
		return false;
	}
	rv = sqlite3_bind_int64(sql, 1, oid);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't bind the object id: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sql);
		return false;
	}
	sqlite3_bind_int64(sql, 2, id);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't bind the attribute id: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sql);
		return false;
	}
	while ((rv = sqlite3_step(sql)) == SQLITE_BUSY)
	{
		sched_yield();
	}
	if (rv != SQLITE_ROW)
	{
		fprintf(stderr,
			"can't read binary attribute id=%lld object=%lld: %d(%s)\n",
			id, oid, rv, sqlite3_errmsg(db));
		sqlite3_finalize(sql);
		return false;
	}
	type = sqlite3_column_int64(sql, 0);
	len = sqlite3_column_bytes(sql, 1);
	val = (const uint8_t*) sqlite3_column_blob(sql, 1);
	for (size_t i = 0; i < len; ++i)
	{
		value.push_back(val[i]);
	}
	sqlite3_finalize(sql);

	return true;
}

// Get an array (aka Attribute vector) value
bool getArray(sqlite3* db, long long oid, long long id, uint64_t& type, std::vector<Attribute>& value)
{
	int rv;
	sqlite3_stmt* sql = NULL;
	std::string command = "select type,value from attribute_array where object_id=? and id=?;";
	size_t len;
	const uint8_t* val;

	value.clear();

	rv = sqlite3_prepare_v2(db, command.c_str(), -1, &sql, NULL);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr,
			"can't find array attribute id=%lld object=%lld: %d(%s)\n",
			id, oid, rv, sqlite3_errmsg(db));
		sqlite3_finalize(sql);
		return false;
	}
	rv = sqlite3_bind_int64(sql, 1, oid);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't bind the object id: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sql);
		return false;
	}
	sqlite3_bind_int64(sql, 2, id);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't bind the attribute id: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sql);
		return false;
	}
	while ((rv = sqlite3_step(sql)) == SQLITE_BUSY)
	{
		sched_yield();
	}
	if (rv != SQLITE_ROW)
	{
		fprintf(stderr,
			"can't read array attribute id=%lld object=%lld: %d(%s)\n",
			id, oid, rv, sqlite3_errmsg(db));
		sqlite3_finalize(sql);
		return false;
	}
	type = sqlite3_column_int64(sql, 0);
	len = sqlite3_column_bytes(sql, 1);
	val = (const uint8_t*) sqlite3_column_blob(sql, 1);

// CK_ATTRIBUTE_TYPE type, AttributeKind kind
//  bool -> int, integer -> unsigned long, binary -> unsigned long + vector

	for (size_t pos = 0; pos < len; )
	{
		// finished?
		if (pos == len) break;

		Attribute attr;

		if (pos + sizeof(attr.type) > len)
		{
			fprintf(stderr, "overflow array item type\n");
			sqlite3_finalize(sql);
			return false;
		}
		memcpy(&attr.type, val + pos, sizeof(attr.type));
		pos += sizeof(attr.type);

		if (pos + sizeof(attr.kind) > len)
		{
			fprintf(stderr, "overflow array item kind\n");
			sqlite3_finalize(sql);
			return false;
		}
		memcpy(&attr.kind, val + pos, sizeof(attr.kind));
		pos += sizeof(attr.kind);

		if (attr.kind == akBoolean)
		{
			if (pos + sizeof(attr.boolValue) > len)
			{
				fprintf(stderr, "overflow array boolean item\n");
				sqlite3_finalize(sql);
				return false;
			}
			memcpy(&attr.boolValue, val + pos, sizeof(attr.boolValue));
			pos += sizeof(attr.boolValue);
		}
		else if (attr.kind == akInteger)
		{
			if (pos + sizeof(attr.ulongValue) > len)
			{
				fprintf(stderr, "overflow array integer item\n");
				sqlite3_finalize(sql);
				return false;
			}
			memcpy(&attr.ulongValue, val + pos, sizeof(attr.ulongValue));
			pos += sizeof(attr.ulongValue);
		}
		else if (attr.kind == akBinary)
		{
			unsigned long size;
			if (pos + sizeof(size) > len)
			{
				fprintf(stderr, "overflow array binary item\n");
				sqlite3_finalize(sql);
				return false;
			}
			memcpy(&size, val + pos, sizeof(size));
			pos += sizeof(size);

			if (pos + size > len)
			{
				fprintf(stderr, "overflow array binary item\n");
				sqlite3_finalize(sql);
				return false;
			}
			attr.bytestrValue.resize(size);
			for (unsigned long i = 0; i < size; ++i)
			{
				attr.bytestrValue[i] = val[pos + i];
			}
			pos += size;
		}
		else
		{
			fprintf(stderr, "unknown array item\n");
			sqlite3_finalize(sql);
			return false;
		}

		value.push_back(attr);
	}
	sqlite3_finalize(sql);

	return true;
}

// Dump boolean attributes of an object
void dump_booleans(sqlite3* db, long long oid)
{
	int rv;
	unsigned long count;
	sqlite3_stmt* sqlcnt = NULL;
	sqlite3_stmt* sqlid = NULL;
	std::string commandcnt = "select count(id) from attribute_boolean where object_id=?;";
	std::string commandid = "select id from attribute_boolean where object_id=?;";
	rv = sqlite3_prepare_v2(db, commandcnt.c_str(), -1, &sqlcnt, NULL);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't count the object table: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlcnt);
		return;
	}
	rv = sqlite3_bind_int64(sqlcnt, 1, oid);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't bind the object id: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlcnt);
		return;
	}
	while ((rv = sqlite3_step(sqlcnt)) == SQLITE_BUSY)
	{
		sched_yield();
	}
	if (rv != SQLITE_ROW)
	{
		fprintf(stderr, "can't count the object table: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlcnt);
		return;
	}
	count = sqlite3_column_int(sqlcnt, 0);
	sqlite3_finalize(sqlcnt);
	if (count == 0)
		return;

	printf("%lu boolean attributes for object %lld\n", count, oid);

	rv = sqlite3_prepare_v2(db, commandid.c_str(), -1, &sqlid, NULL);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't count the object table: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlid);
		return;
	}
	rv = sqlite3_bind_int64(sqlid, 1, oid);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't bind the object id: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlid);
		return;
	}
	while (count-- > 0) {
		while ((rv = sqlite3_step(sqlid)) == SQLITE_BUSY)
		{
			sched_yield();
		}
		if (rv != SQLITE_ROW)
		{
			if (rv != SQLITE_DONE)
			{
				fprintf(stderr,
					"can't get next object id: %d(%s)\n",
					rv, sqlite3_errmsg(db));
			}
			sqlite3_finalize(sqlid);
			return;
		}
		long long id = sqlite3_column_int64(sqlid, 0);

		uint64_t type;
		uint8_t value;
		if (!getBool(db, oid, id, type, value))
		{
			return;
		}
		dumpULong(type);
		if ((uint64_t)((uint32_t)type) != type)
		{
			printf("overflow attribute type\n");
		}
		else
		{
			dumpCKA((unsigned long) type, 48);
			printf("\n");
		}

		dumpBool1(value);
		printf("\n");
	}
}

// Dump integer attributes of an object
void dump_integers(sqlite3* db, long long oid)
{
	int rv;
	unsigned long count;
	sqlite3_stmt* sqlcnt = NULL;
	sqlite3_stmt* sqlid = NULL;
	std::string commandcnt = "select count(id) from attribute_integer where object_id=?;";
	std::string commandid = "select id from attribute_integer where object_id=?;";
	rv = sqlite3_prepare_v2(db, commandcnt.c_str(), -1, &sqlcnt, NULL);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't count the object table: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlcnt);
		return;
	}
	rv = sqlite3_bind_int64(sqlcnt, 1, oid);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't bind the object id: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlcnt);
		return;
	}
	while ((rv = sqlite3_step(sqlcnt)) == SQLITE_BUSY)
	{
		sched_yield();
	}
	if (rv != SQLITE_ROW)
	{
		fprintf(stderr, "can't count the object table: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlcnt);
		return;
	}
	count = sqlite3_column_int(sqlcnt, 0);
	sqlite3_finalize(sqlcnt);
	if (count == 0)
		return;

	printf("%lu integer attributes for object %lld\n", count, oid);

	rv = sqlite3_prepare_v2(db, commandid.c_str(), -1, &sqlid, NULL);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't count the object table: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlid);
		return;
	}
	rv = sqlite3_bind_int64(sqlid, 1, oid);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't bind the object id: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlid);
		return;
	}
	while (count-- > 0) {
		while ((rv = sqlite3_step(sqlid)) == SQLITE_BUSY)
		{
			sched_yield();
		}
		if (rv != SQLITE_ROW)
		{
			if (rv != SQLITE_DONE)
			{
				fprintf(stderr,
					"can't get next object id: %d(%s)\n",
					rv, sqlite3_errmsg(db));
			}
			sqlite3_finalize(sqlid);
			return;
		}
		long long id = sqlite3_column_int64(sqlid, 0);

		uint64_t type;
		uint64_t value;
		if (!getULong(db, oid, id, type, value))
		{
			return;
		}
		dumpULong(type);
		if ((uint64_t)((uint32_t)type) != type)
		{
			printf("overflow attribute type\n");
		}
		else
		{
			dumpCKA((unsigned long) type, 48);
			printf("\n");
		}
		dumpULong(value);
		dumpCKx(type, value, 48);
		printf("\n");
	}
}

// Dump binary attributes of an object
void dump_binaries(sqlite3* db, long long oid)
{
	int rv;
	unsigned long count;
	sqlite3_stmt* sqlcnt = NULL;
	sqlite3_stmt* sqlid = NULL;
	std::string commandcnt = "select count(id) from attribute_binary where object_id=?;";
	std::string commandid = "select id from attribute_binary where object_id=?;";
	rv = sqlite3_prepare_v2(db, commandcnt.c_str(), -1, &sqlcnt, NULL);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't count the object table: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlcnt);
		return;
	}
	rv = sqlite3_bind_int64(sqlcnt, 1, oid);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't bind the object id: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlcnt);
		return;
	}
	while ((rv = sqlite3_step(sqlcnt)) == SQLITE_BUSY)
	{
		sched_yield();
	}
	if (rv != SQLITE_ROW)
	{
		fprintf(stderr, "can't count the object table: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlcnt);
		return;
	}
	count = sqlite3_column_int(sqlcnt, 0);
	sqlite3_finalize(sqlcnt);
	if (count == 0)
		return;

	printf("%lu binary attributes for object %lld\n", count, oid);

	rv = sqlite3_prepare_v2(db, commandid.c_str(), -1, &sqlid, NULL);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't count the object table: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlid);
		return;
	}
	rv = sqlite3_bind_int64(sqlid, 1, oid);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't bind the object id: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlid);
		return;
	}
	while (count-- > 0) {
		while ((rv = sqlite3_step(sqlid)) == SQLITE_BUSY)
		{
			sched_yield();
		}
		if (rv != SQLITE_ROW)
		{
			if (rv != SQLITE_DONE)
			{
				fprintf(stderr,
					"can't get next object id: %d(%s)\n",
					rv, sqlite3_errmsg(db));
			}
			sqlite3_finalize(sqlid);
			return;
		}
		long long id = sqlite3_column_int64(sqlid, 0);

		uint64_t type;
		std::vector<uint8_t> value;
		if (!getBytes(db, oid, id, type, value))
		{
			return;
		}
		dumpULong(type);
		if ((uint64_t)((uint32_t)type) != type)
		{
			printf("overflow attribute type\n");
		}
		else
		{
			dumpCKA((unsigned long) type, 48);
			printf("\n");
		}
		dumpULong((uint64_t) value.size());
		printf("(length %lu)\n", (unsigned long) value.size());
		dumpBytes(value);
	}
}

// Dump array attributes of an object
void dump_arrays(sqlite3* db, long long oid)
{
	int rv;
	unsigned long count;
	sqlite3_stmt* sqlcnt = NULL;
	sqlite3_stmt* sqlid = NULL;
	std::string commandcnt = "select count(id) from attribute_array where object_id=?;";
	std::string commandid = "select id from attribute_array where object_id=?;";
	rv = sqlite3_prepare_v2(db, commandcnt.c_str(), -1, &sqlcnt, NULL);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't count the object table: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlcnt);
		return;
	}
	rv = sqlite3_bind_int64(sqlcnt, 1, oid);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't bind the object id: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlcnt);
		return;
	}
	while ((rv = sqlite3_step(sqlcnt)) == SQLITE_BUSY)
	{
		sched_yield();
	}
	if (rv != SQLITE_ROW)
	{
		fprintf(stderr, "can't count the object table: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlcnt);
		return;
	}
	count = sqlite3_column_int(sqlcnt, 0);
	sqlite3_finalize(sqlcnt);
	if (count == 0)
		return;

	printf("%lu array attributes for object %lld\n", count, oid);

	rv = sqlite3_prepare_v2(db, commandid.c_str(), -1, &sqlid, NULL);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't count the object table: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlid);
		return;
	}
	rv = sqlite3_bind_int64(sqlid, 1, oid);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't bind the object id: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlid);
		return;
	}
	while (count-- > 0) {
		while ((rv = sqlite3_step(sqlid)) == SQLITE_BUSY)
		{
			sched_yield();
		}
		if (rv != SQLITE_ROW)
		{
			if (rv != SQLITE_DONE)
			{
				fprintf(stderr,
					"can't get next object id: %d(%s)\n",
					rv, sqlite3_errmsg(db));
			}
			sqlite3_finalize(sqlid);
			return;
		}
		long long id = sqlite3_column_int64(sqlid, 0);

		uint64_t type;
		std::vector<Attribute> value;
		if (!getArray(db, oid, id, type, value))
		{
			return;
		}
		dumpULong(type);
		if ((uint64_t)((uint32_t)type) != type)
		{
			printf("overflow attribute type\n");
		}
		else
		{
			dumpCKA((unsigned long) type, 48);
			printf("\n");
		}
		dumpULong((uint64_t) value.size());
		printf("(length %lu)\n", (unsigned long) value.size());
		dumpArray(value);
	}
}

// Dump an object
void dump_object(sqlite3* db, long long oid)
{
	printf("dump object id=%lld\n", oid);
	dump_booleans(db, oid);
	dump_integers(db, oid);
	dump_binaries(db, oid);
	dump_arrays(db, oid);
}

// Core function
void dump(sqlite3* db)
{
	int rv;
	unsigned long count;
	sqlite3_stmt* sqlcnt = NULL;
	sqlite3_stmt* sqlid = NULL;
	std::string commandcnt = "select count(id) from object;";
	std::string commandid =  "select id from object;";

	rv = sqlite3_prepare_v2(db, commandcnt.c_str(), -1, &sqlcnt, NULL);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't count the object table: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlcnt);
		return;
	}
	while ((rv = sqlite3_step(sqlcnt)) == SQLITE_BUSY)
	{
		sched_yield();
	}
	if (rv != SQLITE_ROW)
	{
		fprintf(stderr, "can't count the object table: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlcnt);
		return;
	}
	count = sqlite3_column_int(sqlcnt, 0);
	sqlite3_finalize(sqlcnt);
	printf("%lu objects\n", count);

	rv = sqlite3_prepare_v2(db, commandid.c_str(), -1, &sqlid, NULL);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't count the object table: %d(%s)\n",
			rv, sqlite3_errmsg(db));
		sqlite3_finalize(sqlid);
		return;
	}
	while (count-- > 0) {
		while ((rv = sqlite3_step(sqlid)) == SQLITE_BUSY)
		{
			sched_yield();
		}
		if (rv != SQLITE_ROW)
		{
			if (rv != SQLITE_DONE)
			{
				fprintf(stderr,
					"can't get next object id: %d(%s)\n",
					rv, sqlite3_errmsg(db));
			}
			sqlite3_finalize(sqlid);
			return;
		}
		long long oid = sqlite3_column_int64(sqlid, 0);
		dump_object(db, oid);
	}
}

// Display the usage
void usage()
{
	printf("SoftHSM dump tool. From SoftHSM v2 database.\n");
	printf("Usage: softhsm2-dump-db path\n");
}

// Check the existence of a table
void check_table_exist(sqlite3* db, std::string name)
{
	int rv;
	std::string command = "select count(id) from " + name + ";";

	rv = sqlite3_exec(db, command.c_str(), NULL, NULL, NULL);
	if (rv != SQLITE_OK)
	{
		fprintf(stderr, "can't find '%s' table\n", name.c_str());
		sqlite3_close(db);
		exit(0);
	}
}

// The main function
int main(int argc, char* argv[])
{
	int rv;
	sqlite3* db = NULL;

	if (argc != 2)
	{
		usage();
		exit(0);
	}

	rv = sqlite3_open_v2(argv[1], &db, SQLITE_OPEN_READONLY, NULL);
	if (rv != SQLITE_OK)
	{
		if (db == NULL)
		{
			fprintf(stderr,
				"can't open database file %s\n",
				argv[1]);
		}
		else
		{
			fprintf(stderr,
				"can't open database file %s: %d(%s)\n",
				argv[1],
				rv,
				sqlite3_errmsg(db));
		}
		sqlite3_close(db);
		exit(0);
	}

	// No user version to check

	check_table_exist(db, "object");
	check_table_exist(db, "attribute_boolean");
	check_table_exist(db, "attribute_integer");
	check_table_exist(db, "attribute_binary");
	check_table_exist(db, "attribute_array");

	printf("Dump of object file \"%s\"\n", argv[1]);
	dump(db);
	sqlite3_close(db);
	exit(1);
}
