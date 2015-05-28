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
 DB.cpp

 Specifies classes to access the Token Database
 *****************************************************************************/
#define HAVE_SQL_TRACE 0

#include "config.h"
#include "OSPathSep.h"
#include "log.h"
#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <vector>
#include <sqlite3.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "DB.h"

#if HAVE_SQL_TRACE
static void xTrace(void*connectionLabel,const char*zSql)
{
	const char *label = static_cast<const char *>(connectionLabel);
	if (label)
		std::cout << std::endl << label << ": " << zSql ;
	else
		std::cout << std::endl << zSql ;
}
#endif

static int static_log_err(const char *format, va_list ap)
{
	std::vector<char> logMessage;
	logMessage.resize(4096);
	vsnprintf(&logMessage[0], 4096, format, ap);
	ERROR_MSG(&logMessage[0]);
	return 0;
}

static DB::LogErrorHandler static_LogErrorhandler = static_log_err;

void DB::logError(const std::string &format, ...)
{
	if (!static_LogErrorhandler)
		return;
	va_list args;
	va_start(args, format);
	static_LogErrorhandler(format.c_str(),args);
	va_end(args);
}

DB::LogErrorHandler DB::setLogErrorHandler(DB::LogErrorHandler handler)
{
	LogErrorHandler temp = static_LogErrorhandler;
	static_LogErrorhandler = handler;
	return temp;
}

void DB::resetLogErrorHandler()
{
	static_LogErrorhandler = static_log_err;
}

static void reportErrorDB(sqlite3 *db)
{
	if (!db) {
		DB::logError("sqlite3 pointer is NULL");
		return;
	}

	int rv = sqlite3_errcode(db);
	if (rv == SQLITE_OK || rv == SQLITE_ROW || rv == SQLITE_DONE)
		return;

#ifdef HAVE_SILENT_BUSY_AND_LOCKED_ERRORS
	// Either the database file is locked (SQLITE_BUSY)
	// or a table in the database is locked (SQLITE_LOCKED)
	if (rv == SQLITE_BUSY || rv == SQLITE_LOCKED)
		return;
#endif

	DB::logError("SQLITE3: %s (%d)", sqlite3_errmsg(db), rv);
}

static void reportError(sqlite3_stmt *stmt)
{
	if (!stmt) {
		DB::logError("sqlite3_stmt pointer is NULL");
		return;
	}
	reportErrorDB(sqlite3_db_handle(stmt));
}

static time_t sqlite3_gmtime(struct tm *tm)
{
	// We don't want to depend on timegm() so we use a workaround via the
	// gmtime_r() function to determine this.
	// As input we use a moment in time just 10 days after the POSIX epoch.
	// The POSIX epoch is defined as the moment in time at midnight Coordinated
	// Universal Time (UTC) of Thursday, January 1, 1970. A time_t value is
	// the number of seconds elapsed since epoch.
	struct tm ref_tm = {0,0,0,0,0,0,0,0,0,0,0};
	ref_tm.tm_year = 70; // Years since 1900;
	ref_tm.tm_mday = 10; // 10th

	// We need the time difference between local time and UTC time.
	// mktime will interpret the UTC time stored in tm as local time
	// so let's assume we are in a time zone 1 hour ahead of UTC (UTC+1)
	// then a time of 13:00 interpreted as local time needs 1 hour subtracted
	// to arrive at UTC time. This UTC time is then converted to a POSIX
	// time_t value.
	time_t posix_time = mktime(&ref_tm);

	// Use gmtime_r to convert the POSIX time back to a tm struct.
	// No time adjustment is done this time because POSIX time is
	// defined in terms of UTC.
	gmtime_r(&posix_time, &ref_tm);
	if (ref_tm.tm_isdst != 0) {
		DB::logError("expected gmtime_r to return zero in tm_isdst member of tm struct");
		return ((time_t)-1);
	}

	// Using mktime again to convert tm. This will again subtract 1 hour from
	// the time (under the assumption that we are 1 hour ahead of UTC).
	// We can now use this to determine how much local time differred
	// from UTC time on january the 10th 1970
	long diff_time = posix_time - mktime(&ref_tm);

	// We explicitly set tm_isdst to zero to prevent errors
	// when the time we are trying to convert is occuring at
	// the moment when a dst change is in progress.
	// We require mktime to respect our setting of tm_isdst
	// indicating that no dst is in effect.
	tm->tm_isdst = 0; // Tell (and force) mktime not to take dst into account.

	// We now can calculate and return a correct POSIX time.
	// So, although mktime() interprets gm_tm as local time adjusts for
	// the time difference between local time and UTC time. We then undo
	// that adjustment by adding diff_time.
	return mktime(tm) + diff_time;
}

/**************************
 * Handle
 **************************/

class DB::Handle {
public:
	int _refcount;
	sqlite3_stmt *_stmt;
	Handle(sqlite3_stmt *stmt)
		: _refcount(1), _stmt(stmt)
	{
	}
	~Handle()
	{
		if (_stmt)
		{
			sqlite3_finalize(_stmt);
			_stmt = NULL;
		}
	}

	Handle *retain()
	{
		if (_refcount)
		{
			_refcount++;
			return this;
		}
		return NULL;
	}
	void release()
	{
		if (_refcount)
		{
			_refcount--;
			if (_refcount)
				return;
			delete this;
		}
	}
	bool reset()
	{
		if (sqlite3_reset(_stmt) != SQLITE_OK)
		{
			reportError(_stmt);
			return false;
		}
		return true;
	}
	Statement::ReturnCode step()
	{
		int rv = sqlite3_step(_stmt);
		if (rv != SQLITE_ROW && rv != SQLITE_DONE)
		{
			reportError(_stmt);
			return Statement::ReturnCodeError;
		}

		if (rv==SQLITE_ROW)
		{
			return Statement::ReturnCodeRow;
		}

		return Statement::ReturnCodeDone;
	}
private:
	// disable evil constructors
	Handle(const Handle &);
	Handle & operator=(const Handle &);
};

DB::Statement::Statement()
	: _handle(NULL)
{
}

DB::Statement::Statement(sqlite3_stmt *statement)
	: _handle(new Handle(statement))
{
}

DB::Statement::Statement(const DB::Statement &statement)
	: _handle(statement._handle)
{
	if (_handle)
		_handle = _handle->retain();
}

DB::Statement &DB::Statement::operator=(const DB::Statement &statement)
{
	if (this != &statement)
	{
		Handle *tmp = NULL;
		if (statement._handle) {
			tmp = statement._handle->retain();
		}
		if (_handle) {
			_handle->release();
		}
		_handle = tmp;
	}
	return *this;
}

DB::Statement::~Statement()
{
	if (_handle) {
		_handle->release();
		_handle = NULL;
	}
}

bool DB::Statement::isValid()
{
	return _handle != NULL && _handle->_stmt != NULL;
}

int DB::Statement::refcount()
{
	return _handle ? _handle->_refcount : 0;
}


bool DB::Statement::reset()
{
	if (!isValid()) {
		DB::logError("Statement::reset: statement is not valid");
		return false;
	}
	return _handle->reset();
}

DB::Statement::ReturnCode DB::Statement::step()
{
	if (!isValid()) {
		DB::logError("Statement::step: statement is not valid");
		return ReturnCodeError;
	}
	return _handle->step();
}

DB::Handle *DB::Statement::handle() const
{
	return _handle;
}

/**************************
 * Bindings
 **************************/

DB::Bindings::Bindings()
	: Statement()
{
}

DB::Bindings::Bindings(const Statement &statement)
	: Statement(statement)
{
}

bool DB::Bindings::clear()
{
	if (!isValid()) {
		DB::logError("Bindings::clear: statement is not valid");
		return false;
	}
	if (sqlite3_clear_bindings(_handle->_stmt) != SQLITE_OK) {
		reportError(_handle->_stmt);
		return false;
	}
	return true;
}

bool DB::Bindings::bindBlob(int index, const void *value, int n, void(*destruct)(void*))
{
	if (!isValid()) {
		DB::logError("Bindings::bindBlob: statement is not valid");
		return false;
	}
	if (sqlite3_bind_blob(_handle->_stmt, index, value, n, destruct) != SQLITE_OK) {
		reportError(_handle->_stmt);
		return false;
	}
	return true;
}

bool DB::Bindings::bindDouble(int index, double value)
{
	if (!isValid()) {
		DB::logError("Bindings::bindDouble: statement is not valid");
		return false;
	}
	if (sqlite3_bind_double(_handle->_stmt, index, value) != SQLITE_OK) {
		reportError(_handle->_stmt);
		return false;
	}
	return true;
}

bool DB::Bindings::bindInt(int index, int value)
{
	if (!isValid()) {
		DB::logError("Bindings::bindInt: statement is not valid");
		return false;
	}
	if (sqlite3_bind_int(_handle->_stmt, index, value) != SQLITE_OK) {
		reportError(_handle->_stmt);
		return false;
	}
	return true;
}

bool DB::Bindings::bindInt64(int index, long long value)
{
	if (!isValid()) {
		DB::logError("Bindings::bindInt64: statement is not valid");
		return false;
	}
	if (sqlite3_bind_int64(_handle->_stmt, index, value) != SQLITE_OK) {
		reportError(_handle->_stmt);
		return false;
	}
	return true;
}

//bool DB::Bindings::bindNull(int index)
//{
//#if 0
//	int sqlite3_bind_null(sqlite3_stmt*, int);
//#endif
//	return false;
//}

bool DB::Bindings::bindText(int index, const char *value, int n, void (*destruct)(void *))
{
	if (!isValid()) {
		DB::logError("Bindings::bindText: statement is not valid");
		return false;
	}
	if (sqlite3_bind_text(_handle->_stmt, index, value, n, destruct) != SQLITE_OK) {
		reportError(_handle->_stmt);
		return false;
	}
	return true;
}

//bool DB::Bindings::bindZeroBlob(int index, int n)
//{
//#if 0
//	int sqlite3_bind_zeroblob(sqlite3_stmt*, int, int n);
//#endif
//	return false;
//}

/**************************
 * Result
 **************************/

DB::Result::Result()
	: Statement()
{
}

DB::Result::Result(const Statement &statement)
	: Statement(statement)
{
}

#if 0
unsigned int DB::Result::getField(const std::string &fieldname)
{
	unsigned int fieldidx = fields[fieldname];
	if (fieldidx == 0)
		DB::logError("Result: invalid field name \"%s\"",fieldname.c_str());
	return fieldidx;
}
#endif

bool DB::Result::fieldIsNull(unsigned int fieldidx)
{
	if (!isValid()) {
		DB::logError("Result::fieldIsNull: statement is not valid");
		return true;
	}
	if (fieldidx == 0) {
		DB::logError("Result: zero is an invalid field index");
		return true;
	}
	int column_type = sqlite3_column_type(_handle->_stmt, fieldidx-1);
	return column_type == SQLITE_NULL;
}

time_t DB::Result::getDatetime(unsigned int fieldidx)
{
	if (!isValid()) {
		DB::logError("Result::getDatetime: statement is not valid");
		return ((time_t)-1);
	}
	if (fieldidx == 0) {
		DB::logError("Result: zero is an invalid field index");
		return ((time_t)-1);
	}

	const unsigned char *value = sqlite3_column_text(_handle->_stmt, fieldidx-1);
	int valuelen = sqlite3_column_bytes(_handle->_stmt, fieldidx-1);

	unsigned long years,mons,days,hours,mins,secs;
	struct tm gm_tm = {0,0,0,0,0,0,0,0,0,0,0};
	gm_tm.tm_isdst = 0; // Tell mktime not to take dst into account.
	gm_tm.tm_year = 70; // 1970
	gm_tm.tm_mday = 1; // 1th day of the month
	const char *p = (const char *)value;
	char *pnext;
	bool bdateonly = true;
	switch (valuelen) {
		case 19:	// 2011-12-31 23:59:59
			bdateonly = false;
			// falls through to next case
		case 10:	// 2011-12-31
			years = strtoul(p,&pnext,10);
			gm_tm.tm_year = ((int)years)-1900; /* years since 1900 */
			p = pnext+1;
			mons = strtoul(p,&pnext,10);
			gm_tm.tm_mon = ((int)mons)-1; /* months since January [0-11] */
			p = pnext+1;
			days = strtoul(p,&pnext,10);
			gm_tm.tm_mday = ((int)days); /* day of the month [1-31] */
			p = pnext+1;
			if (bdateonly)
				break;
			// falls through to next case
		case 8:		// 23:59:59
			hours = strtoul(p,&pnext,10);
			gm_tm.tm_hour = (int)hours; /* hours since midnight [0-23] */
			if ((pnext-p) != 2) {
				DB::logError("Result: invalid hours in time: '%s'",value);
				return 0;
			}
			p = pnext+1;
			mins = strtoul(p,&pnext,10);
			gm_tm.tm_min = (int)mins; /* minutes after the hour [0-59] */
			if ((pnext-p) != 2) {
				DB::logError("Result: invalid minutes in time: '%s'",value);
				return 0;
			}
			p = pnext+1;
			secs = strtoul(p,&pnext,10);
			gm_tm.tm_sec = (int)secs; /* seconds after the minute [0-60] */
			if ((pnext-p) != 2) {
				DB::logError("Result: invalid seconds in time: '%s'",value);
				return 0;
			}
			break;
		default:
			DB::logError("Result: invalid date/time value: '%s'",value);
			return 0;
	}

	return sqlite3_gmtime(&gm_tm);
}

unsigned char DB::Result::getUChar(unsigned int fieldidx)
{
	if (!isValid()) {
		DB::logError("Result::getUChar: statement is not valid");
		return 0;
	}
	if (fieldidx == 0) {
		DB::logError("Result: zero is an invalid field index");
		return 0;
	}
	int value = sqlite3_column_int(_handle->_stmt, fieldidx-1);
	reportError(_handle->_stmt);
	return (unsigned char)value;
}

float DB::Result::getFloat(unsigned int fieldidx)
{
	if (!isValid()) {
		DB::logError("Result::getFloat: statement is not valid");
		return 0.0f;
	}
	if (fieldidx == 0) {
		DB::logError("Result: zero is an invalid field index");
		return 0.0f;
	}
	double value = sqlite3_column_double(_handle->_stmt, fieldidx-1);
	reportError(_handle->_stmt);
	return (float)value;
}

double DB::Result::getDouble(unsigned int fieldidx)
{
	if (!isValid()) {
		DB::logError("Result::getDouble: statement is not valid");
		return 0.0;
	}
	if (fieldidx == 0) {
		DB::logError("Result: zero is an invalid field index");
		return 0.0;
	}
	double value = sqlite3_column_double(_handle->_stmt, fieldidx-1);
	reportError(_handle->_stmt);
	return value;
}

int DB::Result::getInt(unsigned int fieldidx)
{
	if (!isValid()) {
		DB::logError("Result::getInt: statement is not valid");
		return 0;
	}
	if (fieldidx == 0) {
		DB::logError("Result: zero is an invalid field index");
		return 0;
	}
	int value = sqlite3_column_int(_handle->_stmt, fieldidx-1);
	reportError(_handle->_stmt);
	return value;
}

unsigned int DB::Result::getUInt(unsigned int fieldidx)
{
	if (!isValid()) {
		DB::logError("Result::getUInt: statement is not valid");
		return 0;
	}
	if (fieldidx == 0) {
		DB::logError("Result: zero is an invalid field index");
		return 0;
	}
	int value = sqlite3_column_int(_handle->_stmt, fieldidx-1);
	reportError(_handle->_stmt);
	return (unsigned int)value;
}

long long DB::Result::getLongLong(unsigned int fieldidx)
{
	if (!isValid()) {
		DB::logError("Result::getLongLong: statement is not valid");
		return 0;
	}
	if (fieldidx == 0) {
		DB::logError("Result: zero is an invalid field index");
		return 0;
	}
	sqlite3_int64 value = sqlite3_column_int64(_handle->_stmt, fieldidx-1);
	reportError(_handle->_stmt);
	return value;
}

unsigned long long DB::Result::getULongLong(unsigned int fieldidx)
{
	if (!isValid()) {
		DB::logError("Result::getULongLong: statement is not valid");
		return 0;
	}
	if (fieldidx == 0) {
		DB::logError("Result: zero is an invalid field index");
		return 0;
	}
	sqlite3_int64 value = sqlite3_column_int64(_handle->_stmt, fieldidx-1);
	reportError(_handle->_stmt);
	return (unsigned long long)value;
}

const char *DB::Result::getString(unsigned int fieldidx)
{
	if (!isValid()) {
		DB::logError("Result::getString: statement is not valid");
		return NULL;
	}
	if (fieldidx == 0) {
		DB::logError("Result: zero is an invalid field index");
		return NULL;
	}
	const unsigned char *value = sqlite3_column_text(_handle->_stmt,fieldidx-1);
	reportError(_handle->_stmt);
	return (const char *)value;
}

const unsigned char *DB::Result::getBinary(unsigned int fieldidx)
{
	if (!isValid()) {
		DB::logError("Result::getBinary: statement is not valid");
		return NULL;
	}
	if (fieldidx == 0) {
		DB::logError("Result: zero is an invalid field index");
		return NULL;
	}
	const unsigned char *value =
		(const unsigned char *)sqlite3_column_blob(_handle->_stmt,fieldidx-1);
	reportError(_handle->_stmt);
	return value;
}

size_t DB::Result::getFieldLength(unsigned int fieldidx)
{
	if (!isValid()) {
		DB::logError("Result::getFieldLength: statement is not valid");
		return 0;
	}
	if (fieldidx == 0) {
		DB::logError("Result: zero is an invalid field index");
		return 0;
	}
	int value = sqlite3_column_bytes(_handle->_stmt,fieldidx-1);
	reportError(_handle->_stmt);
	return (size_t)value;
}

bool DB::Result::firstRow()
{
	if (!isValid()) {
		DB::logError("Result::firstRow: statement is not valid");
		return false;
	}
	return _handle->reset() && _handle->step()==Statement::ReturnCodeRow;
}

bool DB::Result::nextRow()
{
	if (!isValid()) {
		DB::logError("Result::nextRow: statement is not valid");
		return false;
	}
	return _handle->step()==Statement::ReturnCodeRow;
}

/**************************
 * Connection
 **************************/

DB::Connection *DB::Connection::Create(const std::string &dbdir, const std::string &dbname)
{
	if (dbdir.length() == 0) {
		DB::logError("Connection::Create: database directory parameter dbdir is empty");
		return NULL;
	}

	if (dbname.length() == 0) {
		DB::logError("Connection::Create: database name parameter dbname is empty");
		return NULL;
	}

	return new Connection(dbdir,dbname);
}

DB::Connection::Connection(const std::string &dbdir, const std::string &dbname)
	: _dbdir(dbdir)
	, _dbpath(dbdir + OS_PATHSEP + dbname)
	, _db(NULL)
{
}

DB::Connection::~Connection()
{
	close();
}

const std::string &DB::Connection::dbdir()
{
	return _dbdir;
}

const std::string &DB::Connection::dbpath()
{
	return _dbpath;
}

DB::Statement DB::Connection::prepare(const std::string &format, ...){
	// pstatement will hold a dynamically allocated string that needs to be deleted.
	char *pstatement = NULL;

	// short form
	char statement[128];
	va_list args;
	va_start(args, format);
	int cneeded = vsnprintf(statement,sizeof(statement),format.c_str(),args);
	va_end(args);
	if (cneeded<0) {
		DB::logError("Connection::prepare: vsnprintf encoding error");
		return Statement();
	}
	if (((size_t)cneeded)>=sizeof(statement)) {
		// long form
		pstatement = new char[cneeded+1];
		if (!pstatement) {
			DB::logError("Connection::prepare: out of memory");
			return Statement();
		}
		va_start(args, format);
		bool ok = vsnprintf(pstatement,cneeded+1,format.c_str(),args)==cneeded;
		va_end(args);
		if (!ok) {
			DB::logError("Connection::prepare: vsnprintf error");
			delete[] pstatement;
			return  Statement();
		}
	}

	sqlite3_stmt *stmt = NULL;
	int rv = sqlite3_prepare_v2(_db,
								pstatement ? pstatement : statement,
								cneeded+1,
								&stmt,
								NULL);

	if (pstatement)
		delete[] pstatement;

	if (rv != SQLITE_OK) {
		reportErrorDB(_db);
		if (stmt)
			sqlite3_finalize(stmt);
		return Statement();
	}

	if (!stmt) {
		DB::logError("Connection::prepare: expected sqlite3_prepare_v2 to return a compiled "
					"statement, got NULL, out of memory ?");
		return Statement();
	}

	return Statement(stmt);
}

DB::Result DB::Connection::perform(DB::Statement &statement)
{
	return (statement.step()==Statement::ReturnCodeRow) ?  Result(statement) : Result();
}

bool DB::Connection::execute(DB::Statement &statement)
{
	return statement.step()==Statement::ReturnCodeDone;
}

bool DB::Connection::connect(const char *
#if HAVE_SQL_TRACE
							 connectionLabel
#endif
							 )
{
	// Create and set file permissions if the DB does not exist.
	int fd = open(_dbpath.c_str(), O_CREAT, S_IRUSR | S_IWUSR);
	if (fd == -1)
	{
		DB::logError("Could not open database: %s (errno %i)",
			     _dbpath.c_str(), errno);
		return false;
	}
	::close(fd);

	int rv = sqlite3_open_v2(_dbpath.c_str(),
							 &_db,
							 SQLITE_OPEN_READWRITE
							 | SQLITE_OPEN_CREATE
							 | SQLITE_OPEN_FULLMUTEX,
							 NULL);

	if (rv != SQLITE_OK) {
		reportErrorDB(_db);
		return false;
	}

	int foreignKeyEnabled = 0;
	rv = sqlite3_db_config(_db,SQLITE_DBCONFIG_ENABLE_FKEY,1,&foreignKeyEnabled);
	if (rv != SQLITE_OK) {
		reportErrorDB(_db);
		return false;
	}

	if (foreignKeyEnabled != 1) {
		DB::logError("Connection::connect: foreign key support not enabled");
		return false;
	}

	rv = sqlite3_busy_timeout(_db, 15000); // 15 seconds
	if (rv != SQLITE_OK) {
		reportErrorDB(_db);
		return false;
	}
#if HAVE_SQL_TRACE
	sqlite3_trace(_db, xTrace, const_cast<char *>(connectionLabel));
#endif
	return true;
}

void DB::Connection::close()
{
	if (_db) {
		sqlite3_close(_db);
		_db = NULL;
	}
}

bool DB::Connection::setBusyTimeout(int ms)
{
	int rv = sqlite3_busy_timeout(_db, ms);
	if (rv != SQLITE_OK) {
		reportErrorDB(_db);
		return false;
	}

	return true;
}

bool DB::Connection::tableExists(const std::string &tablename)
{
	Statement statement = prepare("select name from sqlite_master where type='table' and name='%s';",tablename.c_str());
	return statement.step()==Statement::ReturnCodeRow && statement.step()==Statement::ReturnCodeDone;
}

long long DB::Connection::lastInsertRowId()
{
	return sqlite3_last_insert_rowid(_db);
}

bool DB::Connection::inTransaction()
{
	return sqlite3_get_autocommit(_db)==0;
}

bool DB::Connection::beginTransactionRO()
{
	Statement statement = prepare("begin");
	return statement.step()==Statement::ReturnCodeDone;
}

bool DB::Connection::endTransactionRO()
{
	Statement statement = prepare("end");
	return statement.step()==Statement::ReturnCodeDone;
}

bool DB::Connection::beginTransactionRW()
{
	Statement statement = prepare("begin immediate");
	return statement.step()==Statement::ReturnCodeDone;
}

bool DB::Connection::commitTransaction()
{
	Statement statement = prepare("commit");
	return statement.step()==Statement::ReturnCodeDone;
}

bool DB::Connection::rollbackTransaction()
{
	Statement statement = prepare("rollback");
	return statement.step()==Statement::ReturnCodeDone;
}

