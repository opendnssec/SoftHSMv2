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
 DBTokenTests.h

 Contains test cases to test the database token implementation
 *****************************************************************************/

#ifndef _SOFTHSM_V2_DBTOKENTESTS_H
#define _SOFTHSM_V2_DBTOKENTESTS_H

#include <cppunit/extensions/HelperMacros.h>
#include "DBToken.h"

class test_a_dbtoken : public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE(test_a_dbtoken);
	CPPUNIT_TEST(should_be_creatable);
	CPPUNIT_TEST(should_support_pin_setting_getting);
	CPPUNIT_TEST(should_allow_object_enumeration);
	CPPUNIT_TEST(should_fail_to_open_nonexistant_tokens);
	CPPUNIT_TEST(support_create_delete_objects);
	CPPUNIT_TEST(support_clearing_a_token);
	CPPUNIT_TEST_SUITE_END();

public:
	void setUp();
	void tearDown();

	void should_be_creatable();
	void should_support_pin_setting_getting();
	void should_allow_object_enumeration();
	void should_fail_to_open_nonexistant_tokens();
	void support_create_delete_objects();
	void support_clearing_a_token();

protected:

private:
};

#endif // !_SOFTHSM_V2_DBTOKENTESTS_H
