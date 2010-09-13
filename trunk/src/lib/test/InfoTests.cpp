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

CPPUNIT_TEST_SUITE_REGISTRATION(InfoTests);

void InfoTests::setUp()
{
	setenv("SOFTHSM2_CONF", "./softhsm2.conf", 1);

	slotInvalid = 9999;
	slotWithNoInitToken = 0;
}

void InfoTests::tearDown()
{
	// Just make sure that we finalize any previous failed tests
	C_Finalize(NULL_PTR);
}

void InfoTests::testGetInfo()
{
	CK_RV rv;
	CK_INFO ckInfo;

	// Just make sure that we finalize any previous failed tests
	C_Finalize(NULL_PTR);

	rv = C_GetInfo(&ckInfo);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_GetInfo(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = C_GetInfo(&ckInfo);
	CPPUNIT_ASSERT(rv == CKR_OK);

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

void InfoTests::testGetSlotList()
{
	CK_RV rv;
	CK_ULONG ulSlotCount = 0;
	CK_SLOT_ID_PTR pSlotList;

	// Just make sure that we finalize any previous failed tests
	C_Finalize(NULL_PTR);

	rv = C_GetSlotList(CK_FALSE, NULL_PTR, &ulSlotCount);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_GetSlotList(CK_FALSE, NULL_PTR, NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	// Get the size of the buffer
	rv = C_GetSlotList(CK_FALSE, NULL_PTR, &ulSlotCount);
	CPPUNIT_ASSERT(rv == CKR_OK);
	pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount * sizeof(CK_SLOT_ID));

	// Check if we have a too small buffer
	ulSlotCount = 0;
	rv = C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
	CPPUNIT_ASSERT(rv == CKR_BUFFER_TOO_SMALL);

	// Get the slot list
	rv = C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
	CPPUNIT_ASSERT(rv == CKR_OK);
	free(pSlotList);

	// Get the number of slots with tokens
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &ulSlotCount);
	CPPUNIT_ASSERT(rv == CKR_OK);
	pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount * sizeof(CK_SLOT_ID));

	// Check if we have a too small buffer
	ulSlotCount = 0;
	rv = C_GetSlotList(CK_TRUE, pSlotList, &ulSlotCount);
	CPPUNIT_ASSERT(rv == CKR_BUFFER_TOO_SMALL);

	// Get the slot list
	rv = C_GetSlotList(CK_TRUE, pSlotList, &ulSlotCount);
	CPPUNIT_ASSERT(rv == CKR_OK);
	free(pSlotList);

	C_Finalize(NULL_PTR);
}

void InfoTests::testGetSlotInfo()
{
	CK_RV rv;
	CK_SLOT_INFO slotInfo;

	// Just make sure that we finalize any previous failed tests
	C_Finalize(NULL_PTR);

	rv = C_GetSlotInfo(slotWithNoInitToken, &slotInfo);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_GetSlotInfo(slotWithNoInitToken, NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = C_GetSlotInfo(slotInvalid, &slotInfo);
	CPPUNIT_ASSERT(rv == CKR_SLOT_ID_INVALID);

	rv = C_GetSlotInfo(slotWithNoInitToken, &slotInfo);
	CPPUNIT_ASSERT(rv == CKR_OK);

	C_Finalize(NULL_PTR);
}

void InfoTests::testGetTokenInfo()
{
	CK_RV rv;
	CK_TOKEN_INFO tokenInfo;

	// Just make sure that we finalize any previous failed tests
	C_Finalize(NULL_PTR);

	rv = C_GetTokenInfo(slotWithNoInitToken, &tokenInfo);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_GetTokenInfo(slotWithNoInitToken, NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = C_GetTokenInfo(slotInvalid, &tokenInfo);
	CPPUNIT_ASSERT(rv == CKR_SLOT_ID_INVALID);

	rv = C_GetTokenInfo(slotWithNoInitToken, &tokenInfo);
	CPPUNIT_ASSERT(rv == CKR_OK);

	CPPUNIT_ASSERT((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == 0);

	C_Finalize(NULL_PTR);
}

void InfoTests::testGetMechanismList()
{
	CK_RV rv;
	CK_ULONG ulMechCount = 0;
	CK_MECHANISM_TYPE_PTR pMechanismList;

	// Just make sure that we finalize any previous failed tests
	C_Finalize(NULL_PTR);

	rv = C_GetMechanismList(slotWithNoInitToken, NULL_PTR, &ulMechCount);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_GetMechanismList(slotWithNoInitToken, NULL_PTR, NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = C_GetMechanismList(slotInvalid, NULL_PTR, &ulMechCount);
	CPPUNIT_ASSERT(rv == CKR_SLOT_ID_INVALID);

	// Get the size of the buffer
	rv = C_GetMechanismList(slotWithNoInitToken, NULL_PTR, &ulMechCount);
	CPPUNIT_ASSERT(rv == CKR_OK);
	pMechanismList = (CK_MECHANISM_TYPE_PTR)malloc(ulMechCount * sizeof(CK_MECHANISM_TYPE_PTR));

	// Check if we have a too small buffer
	ulMechCount = 0;
	rv = C_GetMechanismList(slotWithNoInitToken, pMechanismList, &ulMechCount);
	CPPUNIT_ASSERT(rv == CKR_BUFFER_TOO_SMALL);

	// Get the mechanism list
	rv = C_GetMechanismList(slotWithNoInitToken, pMechanismList, &ulMechCount);
	CPPUNIT_ASSERT(rv == CKR_OK);
	free(pMechanismList);

	C_Finalize(NULL_PTR);
}

void InfoTests::testGetMechanismInfo()
{
	CK_RV rv;
	CK_MECHANISM_INFO info;
	CK_ULONG ulMechCount = 0;
	CK_MECHANISM_TYPE_PTR pMechanismList;

	// Just make sure that we finalize any previous failed tests
	C_Finalize(NULL_PTR);

	rv = C_GetMechanismInfo(slotWithNoInitToken, CKM_RSA_PKCS, &info);
	CPPUNIT_ASSERT(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	rv = C_Initialize(NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_OK);

	// Get the mechanism list
	rv = C_GetMechanismList(slotWithNoInitToken, NULL_PTR, &ulMechCount);
	CPPUNIT_ASSERT(rv == CKR_OK);
	CPPUNIT_ASSERT(ulMechCount != 0);
	pMechanismList = (CK_MECHANISM_TYPE_PTR)malloc(ulMechCount * sizeof(CK_MECHANISM_TYPE_PTR));
	rv = C_GetMechanismList(slotWithNoInitToken, pMechanismList, &ulMechCount);
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = C_GetMechanismInfo(slotWithNoInitToken, pMechanismList[0], NULL_PTR);
	CPPUNIT_ASSERT(rv == CKR_ARGUMENTS_BAD);

	rv = C_GetMechanismInfo(slotInvalid, pMechanismList[0], &info);
	CPPUNIT_ASSERT(rv == CKR_SLOT_ID_INVALID);

	rv = C_GetMechanismInfo(slotWithNoInitToken, CKM_VENDOR_DEFINED, &info);
	CPPUNIT_ASSERT(rv == CKR_MECHANISM_INVALID);

	for (int i = 0; i < ulMechCount; i++)
	{
		rv = C_GetMechanismInfo(slotWithNoInitToken, pMechanismList[i], &info);
		CPPUNIT_ASSERT(rv == CKR_OK);
	}

	free(pMechanismList);

	C_Finalize(NULL_PTR);
}
