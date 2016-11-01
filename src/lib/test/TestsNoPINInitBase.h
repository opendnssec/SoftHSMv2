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
 TestsNoPINInitBase.h

 Base class for test classes. Used when there is no need for user login.
 *****************************************************************************/

#ifndef SRC_LIB_TEST_TESTSNOPININITBASE_H_
#define SRC_LIB_TEST_TESTSNOPININITBASE_H_

#include "cryptoki.h"
#include <cppunit/TestFixture.h>


#ifdef P11M
#define CRYPTOKI_F_PTR(func) m_ptr->func
#else
#define CRYPTOKI_F_PTR(func) func
#endif

class TestsNoPINInitBase : public CppUnit::TestFixture {
public:
	TestsNoPINInitBase();
	virtual ~TestsNoPINInitBase();

	virtual void setUp();
	virtual void tearDown();
private:
	void getSlotIDs();
#ifdef P11M
#ifdef _WIN32
	HINSTANCE__* p11Library;
#else
	void *const p11Library;
#endif
protected:
	const CK_FUNCTION_LIST_PTR m_ptr;
#else
protected:
#endif
	const CK_SLOT_ID m_invalidSlotID;
	CK_SLOT_ID m_initializedTokenSlotID;
	CK_SLOT_ID m_notInitializedTokenSlotID;

	const CK_UTF8CHAR_PTR m_soPin1;
	const CK_ULONG m_soPin1Length;

	const CK_UTF8CHAR_PTR m_userPin1;
	const CK_ULONG m_userPin1Length;
};


#endif /* SRC_LIB_TEST_TESTSNOPININITBASE_H_ */
