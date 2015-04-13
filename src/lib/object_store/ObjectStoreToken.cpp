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
 ObjectStoreToken.cpp

 The object store abstract token base class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "ObjectStoreToken.h"

// OSToken is a concrete implementation of ObjectStoreToken base class.
#include "OSToken.h"

#ifdef HAVE_OBJECTSTORE_BACKEND_DB
// DBToken is a concrete implementation of ObjectSToreToken that stores the objects and attributes in an SQLite3 database.
#include "DBToken.h"
#endif

typedef ObjectStoreToken* (*CreateToken)(const std::string , const std::string , const ByteString& , const ByteString& );
typedef ObjectStoreToken* (*AccessToken)(const std::string &, const std::string &);

static CreateToken static_createToken = reinterpret_cast<CreateToken>(OSToken::createToken);
static AccessToken static_accessToken = reinterpret_cast<AccessToken>(OSToken::accessToken);

// Create a new token
/*static*/ bool ObjectStoreToken::selectBackend(const std::string &backend)
{
	if (backend == "file")
	{
		static_createToken = reinterpret_cast<CreateToken>(OSToken::createToken);
		static_accessToken = reinterpret_cast<AccessToken>(OSToken::accessToken);
	}
#ifdef HAVE_OBJECTSTORE_BACKEND_DB
	else if (backend == "db")
	{
		static_createToken = reinterpret_cast<CreateToken>(DBToken::createToken);
		static_accessToken = reinterpret_cast<AccessToken>(DBToken::accessToken);
	}
#endif
	else
	{
		ERROR_MSG("Unknown value (%s) for objectstore.backend in configuration", backend.c_str());
		return false;
	}

	return true;
}

ObjectStoreToken* ObjectStoreToken::createToken(const std::string basePath, const std::string tokenDir, const ByteString& label, const ByteString& serial)
{
	return static_createToken(basePath,tokenDir,label,serial);
}

// Access an existing token
/*static*/ ObjectStoreToken *ObjectStoreToken::accessToken(const std::string &basePath, const std::string &tokenDir)
{
	return static_accessToken(basePath, tokenDir);
}
