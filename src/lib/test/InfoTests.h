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
 InfoTests.h

 Contains test cases to C_GetInfo, C_GetFunctionList, C_GetSlotList, 
 C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList, and C_GetMechanismInfo
 *****************************************************************************/

#ifndef _SOFTHSM_V2_INFOTESTS_H
#define _SOFTHSM_V2_INFOTESTS_H

#include "TestsNoPINInitBase.h"
#include <cppunit/extensions/HelperMacros.h>

class InfoTests : public TestsNoPINInitBase
{
	CPPUNIT_TEST_SUITE(InfoTests);
	CPPUNIT_TEST(testGetInfo);
	CPPUNIT_TEST(testGetFunctionList);
	CPPUNIT_TEST(testGetSlotList);
	CPPUNIT_TEST(testGetSlotInfo);
	CPPUNIT_TEST(testGetTokenInfo);
	CPPUNIT_TEST(testGetMechanismList);
	CPPUNIT_TEST(testGetMechanismInfo);
	CPPUNIT_TEST(testGetSlotInfoAlt);
	CPPUNIT_TEST_SUITE_END();

public:
	void testGetInfo();
	void testGetFunctionList();
	void testGetSlotList();
	void testGetSlotInfo();
	void testGetTokenInfo();
	void testGetMechanismList();
	void testGetMechanismInfo();
	void testGetSlotInfoAlt();
};

#endif // !_SOFTHSM_V2_INFOTESTS_H

