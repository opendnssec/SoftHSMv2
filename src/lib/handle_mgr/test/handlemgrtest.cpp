/*
 * Copyright (c) 2012 SURFnet bv
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
 handlemgrtest.cpp

 The main test executor for tests on the handle manager in SoftHSM v2
 *****************************************************************************/

#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/TextOutputter.h>
#include <cppunit/TextTestProgressListener.h>
#include <cppunit/BriefTestProgressListener.h>
#include <cppunit/ui/text/TestRunner.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/XmlOutputter.h>
#include <cppunit/CompilerOutputter.h>
#include <cppunit/portability/Stream.h>


#include <fstream>
#include <time.h>

#include "config.h"
#include "MutexFactory.h"

#ifdef HAVE_CXX11
std::unique_ptr<MutexFactory> MutexFactory::instance(nullptr);
#else
std::auto_ptr<MutexFactory> MutexFactory::instance(NULL);
#endif

class MyProgressListener : public CppUnit::TextTestProgressListener
{
public:
	MyProgressListener(): duration(0) {
		TextTestProgressListener();
	}

	void startTest(CppUnit::Test *test) {
		(test);
		start = clock();
	}

	void endTestRun(CppUnit::Test *test,
		CppUnit::TestResult *eventManager) {
		(eventManager); (test);
		end = clock();
		duration= double(end - start)/ CLOCKS_PER_SEC;
		CppUnit::stdCOut() << "duration " << TimeFormat(duration);

	}

	void startSuite(CPPUNIT_NS::Test *suite) {
		CppUnit::stdCOut() << suite->countTestCases();
	}

	void endTest(CPPUNIT_NS::Test *test) {
		(test);
	}

	double durationTest() const {
		return duration;
	};
private:
	std::string TimeFormat(double time) {
		char buffer[320];
		::sprintf(buffer, "%6f", time);
		return buffer;
	}

	std::string m_name;
	long start, end;
	double duration;
};

int main(int /*argc*/, char** /*argv*/)
{
	CppUnit::TestResult controller;
	CppUnit::TestResultCollector result;
	CppUnit::TextUi::TestRunner runner;
	controller.addListener(&result);
	CppUnit::TestFactoryRegistry &registry = CppUnit::TestFactoryRegistry::getRegistry();

	MyProgressListener progress;
	controller.addListener(&progress);
	
	CppUnit::BriefTestProgressListener progressListener;
	controller.addListener(&progressListener);

	runner.addTest(registry.makeTest());
	runner.run(controller);

	std::ofstream xmlFileOut("test-results.xml");
	CppUnit::XmlOutputter xmlOut(&result, xmlFileOut);
	xmlOut.write();

	CppUnit::TextOutputter consoleOutputter(&result, std::cout);
	consoleOutputter.write();

	return result.wasSuccessful() ? 0 : 1;
}
