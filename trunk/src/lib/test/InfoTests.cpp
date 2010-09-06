/* $Id$ */

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
 InfoTests.cpp

 Contains test cases to C_GetInfo, C_GetFunctionList, C_GetSlotList, 
 C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList, and C_GetMechanismInfo
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "InfoTests.h"
#include "cryptoki.h"

CPPUNIT_TEST_SUITE_REGISTRATION(InfoTests);

// FIXME: all pathnames in this file are *NIX/BSD specific
// FIXME: Should use the real path to the object store

void InfoTests::setUp()
{
	// FIXME: this only works on *NIX/BSD, not on other platforms
	CPPUNIT_ASSERT(!system("mkdir testdir"));
}

void InfoTests::tearDown()
{
	// Just make sure that we finalize any previous failed tests
	C_Finalize(NULL_PTR);

	// FIXME: this only works on *NIX/BSD, not on other platforms
	CPPUNIT_ASSERT(!system("rm -rf testdir"));
}

void InfoTests::testGetInfo()
{
	CK_RV rv;
	CK_INFO ckInfo;

	// Just make sure that we finalize any previous failed tests
	C_Finalize(NULL_PTR);

	rv = C_GetInfo(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED || rv == CKR_ARGUMENTS_BAD);

	if (rv == CKR_CRYPTOKI_NOT_INITIALIZED)
	{
		rv = C_Initialize(NULL_PTR);
		CPPUNIT_ASSERT(rv == CKR_OK);

		rv = C_GetInfo(NULL_PTR);
		CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

		rv = C_GetInfo(&ckInfo);
		CPPUNIT_ASSERT(rv == CKR_OK);
	}
	else
	{
		rv = C_GetInfo(&ckInfo);
		CPPUNIT_ASSERT(rv == CKR_OK || rv == CKR_CRYPTOKI_NOT_INITIALIZED);

		if (rv == CKR_CRYPTOKI_NOT_INITIALIZED)
		{
			rv = C_Initialize(NULL_PTR);
			CPPUNIT_ASSERT(rv == CKR_OK);

			rv = C_GetInfo(&ckInfo);
			CPPUNIT_ASSERT(rv == CKR_OK);
		}
	}

	C_Finalize(NULL_PTR);
}

void InfoTests::testGetFunctionList()
{
	CK_RV rv;
	CK_FUNCTION_LIST_PTR ckFuncList;

	rv = C_GetFunctionList(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = C_GetFunctionList(&ckFuncList);
	CPPUNIT_ASSERT(rv == CKR_OK);
}
