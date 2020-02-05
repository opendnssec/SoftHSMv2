/*
 * Copyright (c) 2020 by Red Hat, Inc.
 *
 * Author: Anderson Toshiyuki Sasaki <ansasaki@redhat.com>
 *
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
 ForkTests.cpp

 Contains test cases for forking scenarios
 *****************************************************************************/
#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "ForkTests.h"
#include "cryptoki.h"
#include "osmutex.h"

#include <sys/types.h>
#include <unistd.h>

CPPUNIT_TEST_SUITE_REGISTRATION(ForkTests);

void ForkTests::setUp()
{

#ifndef _WIN32
	setenv("SOFTHSM2_CONF", "./softhsm2.conf", 1);
#else
	setenv("SOFTHSM2_CONF", ".\\softhsm2.conf", 1);
#endif
}

void ForkTests::tearDown()
{
	// Just make sure that we finalize any previous failed tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
}

void ForkTests::testFork()
{
	CK_RV rv;
	pid_t pid;

	// Just make sure that we finalize any previous failed tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	pid = fork();

	switch(pid) {
		case -1:
			CPPUNIT_FAIL("Fork failed");
			break;
		case 0:
			rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
			CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);
			break;
		default:
			rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
			CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);
			break;
	}

	rv = CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);
}

void ForkTests::testResetOnFork()
{
	CK_RV rv;
	CK_SLOT_INFO slotInfo;
	pid_t pid;

	// Just make sure that we finalize any previous failed tests
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

#ifndef _WIN32
	setenv("SOFTHSM2_CONF", "./softhsm2-reset-on-fork.conf", 1);
#else
	setenv("SOFTHSM2_CONF", ".\\softhsm2-reset-on-fork.conf", 1);
#endif

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	pid = fork();

	switch(pid) {
		case -1:
			CPPUNIT_FAIL("Fork failed");
			break;
		case 0:
			/* For the child, the token is expected to be reset on fork */
			rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
			CPPUNIT_ASSERT(rv == CKR_OK);
			break;
		default:
			/* For the parent, the token is expected to be still initialized */
			rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
			CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);
			break;
	}

	rv = CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

#ifndef _WIN32
	setenv("SOFTHSM2_CONF", "./softhsm2.conf", 1);
#else
	setenv("SOFTHSM2_CONF", ".\\softhsm2.conf", 1);
#endif
}
