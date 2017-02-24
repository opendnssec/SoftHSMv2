/*
 * Copyright (c) 2010 SURFnet bv
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
 cryptotest.cpp

 The main test executor for tests on the cryptographic functions in SoftHSM v2
 *****************************************************************************/

#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/XmlOutputter.h>
#include <fstream>

#include "config.h"
#include "MutexFactory.h"
#include "SecureMemoryRegistry.h"

#if defined(WITH_OPENSSL)
#include "OSSLCryptoFactory.h"
#else
#include "BotanCryptoFactory.h"
#endif

// Initialise the one-and-only instance
#ifdef HAVE_CXX11

std::unique_ptr<MutexFactory> MutexFactory::instance(nullptr);
std::unique_ptr<SecureMemoryRegistry> SecureMemoryRegistry::instance(nullptr);
#if defined(WITH_OPENSSL)
std::unique_ptr<OSSLCryptoFactory> OSSLCryptoFactory::instance(nullptr);
#else
std::unique_ptr<BotanCryptoFactory> BotanCryptoFactory::instance(nullptr);
#endif

#else

std::auto_ptr<MutexFactory> MutexFactory::instance(NULL);
std::auto_ptr<SecureMemoryRegistry> SecureMemoryRegistry::instance(NULL);
#if defined(WITH_OPENSSL)
std::auto_ptr<OSSLCryptoFactory> OSSLCryptoFactory::instance(NULL);
#else
std::auto_ptr<BotanCryptoFactory> BotanCryptoFactory::instance(NULL);
#endif

#endif

int main(int /*argc*/, char** /*argv*/)
{
	CppUnit::TestResult controller;
	CppUnit::TestResultCollector result;
	CppUnit::TextUi::TestRunner runner;
	controller.addListener(&result);
	CppUnit::TestFactoryRegistry &registry = CppUnit::TestFactoryRegistry::getRegistry();

	runner.addTest(registry.makeTest());
	runner.run(controller);

	std::ofstream xmlFileOut("test-results.xml");
	CppUnit::XmlOutputter xmlOut(&result, xmlFileOut);
	xmlOut.write();

	CryptoFactory::reset();

	return result.wasSuccessful() ? 0 : 1;
}
