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
 DB.h

 Specifies classes to access the Token Database
 *****************************************************************************/

#ifndef _SOFTHSM_V2_DB_H
#define _SOFTHSM_V2_DB_H

#include "config.h"

#include <string>
#include <sqlite3.h>

namespace DB {

// Log an error to the error handler that has been setup using a call to setLogErrorHandler declared below.
void logError(const std::string &format, ...);

// The ap parameter has already been started with va_start.
// So the handler only has to pass this on to a vprintf function
// to actually print it.
typedef int (*LogErrorHandler)(const char *format, va_list ap);

// Set an alternative for vprintf to log the actual errors.
// Set to NULL to disable logging al together.
LogErrorHandler setLogErrorHandler(LogErrorHandler handler);

// Set the log error handler back to the default value that logs to stdout.
void resetLogErrorHandler();

// Forward declaration of the handle class used by Statement, Binding and Result.
class Handle;

// Responsible for holding on to a prepared statement.
// After a prepared statement has been used it can be reused when the same query is performed again.
class Statement {
public:
	Statement();
	Statement(sqlite3_stmt *statement);
	Statement(const Statement &statement);
	Statement &operator=(const Statement &statement);

	virtual ~Statement();
	bool isValid();

	// Something we'd like to check during testing.
	int refcount();

	// Reset a prepared statement
	bool reset();

	// Perform a single step of the prepared statement.
	enum ReturnCode {
		ReturnCodeRow,
		ReturnCodeDone,
		ReturnCodeError
	};

	ReturnCode step();

	Handle *handle() const;
protected:
	Handle *_handle;
};

// Responsible for allowing parameters to be bound to statements.
// On a statement that has been performed or executed you first
// need to call reset() before new parameters can be bound.
class Bindings : public Statement {
public:
	Bindings();
	Bindings(const Statement &statement);

	// To clear all existing bindings call this method.
	bool clear();

	// Bind a value to a parameter in a prepared statement
	bool bindBlob(int index, const void *value, int n, void(*destruct)(void*));
	bool bindDouble(int index, double value);
	bool bindInt(int index, int value);
	bool bindInt64(int index, long long value );
	//bool bindNull(int index);
	bool bindText(int index, const char *value, int n, void(*destruct)(void*));
	//bool bindZeroBlob(int index, int n);
};

// Responsible for providing access to the result set of a query.
// Used for queries that actually provide a result set.
// A result that is returned will be positioned at the first row.
class Result : public Statement {
public:
	Result();
	Result(const Statement &statement);

	bool fieldIsNull(unsigned int fieldidx);
	time_t getDatetime(unsigned int fieldidx);
	unsigned char getUChar(unsigned int fieldidx);
	float getFloat(unsigned int fieldidx);
	double getDouble(unsigned int fieldidx);
	int getInt(unsigned int fieldidx);
	unsigned int getUInt(unsigned int fieldidx);
	long long getLongLong(unsigned int fieldidx);
	unsigned long long getULongLong(unsigned int fieldidx);

	const char *getString(unsigned int fieldidx);
	const unsigned char *getBinary(unsigned int fieldidx);
	size_t getFieldLength(unsigned int fieldidx);

	// Position the result on the first row again.
	bool firstRow();

	// Position the result on the next row.
	bool nextRow();
};

// Responsible for connection to the database and for managing prepared statements.
class Connection {
public:
	static Connection *Create(const std::string &dbdir, const std::string &dbname);
	virtual ~Connection();

	// value that was passed into dbdir when this connection was created.
	const std::string &dbdir();

	// concatenation of dbdir and dbname
	const std::string &dbpath();

	Statement prepare(const std::string &format, ...);
	Result perform(Statement &statement);
	bool execute(Statement &statement);

	bool connect(const char *connectionLabel = NULL);
	void close();

	bool tableExists(const std::string &tablename);
	long long lastInsertRowId();

	bool inTransaction();
	bool beginTransactionRO();
	bool endTransactionRO();
	bool beginTransactionRW();
	bool commitTransaction();
	bool rollbackTransaction();

	// Set the busy timeout that the database layer will wait for a database lock to become available.
	bool setBusyTimeout(int ms);
private:
	std::string _dbdir;
	std::string _dbpath;
	sqlite3 *_db;

	Connection(const std::string &dbdir, const std::string &dbname);

	// disable evil constructors
	Connection(const Connection &);
	void operator=(const Connection&);
};

}

#endif // !_SOFTHSM_V2_DB_H
