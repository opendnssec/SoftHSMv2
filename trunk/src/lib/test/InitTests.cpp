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
 InitTests.cpp

 Contains test cases to C_Initialize and C_Finalize
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "InitTests.h"
#include "cryptoki.h"

CPPUNIT_TEST_SUITE_REGISTRATION(InitTests);

// FIXME: all pathnames in this file are *NIX/BSD specific
// FIXME: Should use the real path to the object store

void InitTests::setUp()
{
	// FIXME: this only works on *NIX/BSD, not on other platforms
	CPPUNIT_ASSERT(!system("mkdir testdir"));
}

void InitTests::tearDown()
{
	// Just make sure that we finalize any previous failed tests
	C_Finalize(NULL_PTR);

	// FIXME: this only works on *NIX/BSD, not on other platforms
	CPPUNIT_ASSERT(!system("rm -rf testdir"));
}

void InitTests::testInit1()
{
	CK_RV rv;

	// Just make sure that we finalize any previous failed tests
	C_Finalize(NULL_PTR);

	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);

	rv = C_Finalize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void InitTests::testInit2()
{
	CK_C_INITIALIZE_ARGS InitArgs;
	CK_RV rv;

	InitArgs.CreateMutex = NULL_PTR;
	InitArgs.DestroyMutex = NULL_PTR;
	InitArgs.LockMutex = NULL_PTR;
	InitArgs.UnlockMutex = NULL_PTR;
	InitArgs.flags = 0;
	InitArgs.pReserved = (CK_VOID_PTR)1;

	// Just make sure that we finalize any previous failed tests
	C_Finalize(NULL_PTR);

	rv = C_Initialize((CK_VOID_PTR)&InitArgs);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	InitArgs.pReserved = NULL_PTR;
	rv = C_Initialize((CK_VOID_PTR)&InitArgs);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_Initialize((CK_VOID_PTR)&InitArgs);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);

	rv = C_Finalize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void InitTests::testInit3()
{
	CK_C_INITIALIZE_ARGS InitArgs;
	CK_RV rv;

	InitArgs.CreateMutex = NULL_PTR;
	InitArgs.DestroyMutex = NULL_PTR;
	InitArgs.LockMutex = NULL_PTR;
	InitArgs.UnlockMutex = (CK_UNLOCKMUTEX)1;
	InitArgs.flags = 0;
	InitArgs.pReserved = NULL_PTR;

	// Just make sure that we finalize any previous failed tests
	C_Finalize(NULL_PTR);

	rv = C_Initialize((CK_VOID_PTR)&InitArgs);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	InitArgs.UnlockMutex = NULL_PTR;
	rv = C_Initialize((CK_VOID_PTR)&InitArgs);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_Initialize((CK_VOID_PTR)&InitArgs);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);

	rv = C_Finalize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void InitTests::testInit4()
{
	CK_C_INITIALIZE_ARGS InitArgs;
	CK_RV rv;

	InitArgs.CreateMutex = NULL_PTR;
	InitArgs.DestroyMutex = NULL_PTR;
	InitArgs.LockMutex = NULL_PTR;
	InitArgs.UnlockMutex = (CK_UNLOCKMUTEX)1;
	InitArgs.flags = CKF_OS_LOCKING_OK;
	InitArgs.pReserved = NULL_PTR;

	// Just make sure that we finalize any previous failed tests
	C_Finalize(NULL_PTR);

	rv = C_Initialize((CK_VOID_PTR)&InitArgs);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	InitArgs.UnlockMutex = NULL_PTR;
	rv = C_Initialize((CK_VOID_PTR)&InitArgs);
	// If rv == CKR_CANT_LOCK then we cannot use multiple threads
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_Initialize((CK_VOID_PTR)&InitArgs);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);

	rv = C_Finalize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);
}

// TODO: More tests where we provide the mutex functions

void InitTests::testFinal()
{
	CK_RV rv;

	// Just make sure that we finalize any previous failed tests
	C_Finalize(NULL_PTR);

	rv = C_Finalize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// pReserved is reserved for future versions
	rv = C_Finalize((CK_VOID_PTR)1);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = C_Finalize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);
}
