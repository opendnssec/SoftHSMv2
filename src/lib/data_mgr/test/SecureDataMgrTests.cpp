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
 SecureDataMgrTests.cpp

 Contains test cases to test the secure data manager
 *****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <cppunit/extensions/HelperMacros.h>
#include "SecureDataMgrTests.h"
#include "SecureDataManager.h"
#include "CryptoFactory.h"

CPPUNIT_TEST_SUITE_REGISTRATION(SecureDataMgrTests);

void SecureDataMgrTests::setUp()
{
	CPPUNIT_ASSERT((rng = CryptoFactory::i()->getRNG()) != NULL);
}

void SecureDataMgrTests::tearDown()
{
}

void SecureDataMgrTests::testSecureDataManager()
{
	ByteString soPIN = "3132333435363738"; // "12345678"
	ByteString userPIN = "4041424344454647"; // "ABCDEFGH"
	ByteString newSOPIN = "3837363534333231"; // "87654321"
	ByteString newUserPIN = "4746454443424140"; // "HGFEDCBA"

	// Instantiate a blank secure data manager
	SecureDataManager s1;
	ByteString plaintext = "010203040506070809";
	ByteString emptyPlaintext = "";
	ByteString encrypted;

	// Verify that no function other than setting the SO PIN works
	CPPUNIT_ASSERT(!s1.setUserPIN(userPIN));
	CPPUNIT_ASSERT(!s1.loginSO(soPIN));
	CPPUNIT_ASSERT(!s1.loginUser(userPIN));
	CPPUNIT_ASSERT(!s1.reAuthenticateSO(soPIN));
	CPPUNIT_ASSERT(!s1.reAuthenticateUser(userPIN));
	CPPUNIT_ASSERT(!s1.encrypt(plaintext, encrypted));
	CPPUNIT_ASSERT(!s1.decrypt(encrypted, plaintext));
	CPPUNIT_ASSERT(s1.getSOPINBlob().size() == 0);
	CPPUNIT_ASSERT(s1.getUserPINBlob().size() == 0);

	// Now set the SO PIN
	CPPUNIT_ASSERT(s1.setSOPIN(soPIN));

	// Check that it is still not possible to set the user PIN
	CPPUNIT_ASSERT(!s1.setUserPIN(userPIN));

	// Check that it is possible to log in with the SO PIN
	CPPUNIT_ASSERT(s1.loginSO(soPIN));

	// Check that it is now possible to also set the user PIN
	CPPUNIT_ASSERT(s1.setUserPIN(userPIN));

	// Check that is is now also possible to log in with the user PIN
	CPPUNIT_ASSERT(s1.loginUser(userPIN));

	// Check that it is possible to encrypt and decrypt some data
	ByteString decrypted;

	CPPUNIT_ASSERT(s1.encrypt(plaintext, encrypted));
	CPPUNIT_ASSERT(encrypted != plaintext);

	CPPUNIT_ASSERT(s1.decrypt(encrypted, decrypted));
	CPPUNIT_ASSERT(decrypted == plaintext);

	// Log out
	s1.logout();

	// Check that it is no longer possible to set the SO PIN
	CPPUNIT_ASSERT(!s1.setSOPIN(soPIN));

	// Check that it is no longer possible to set the user PIN
	CPPUNIT_ASSERT(!s1.setUserPIN(userPIN));

	// Check that encrypting/decrypting no longer works
	CPPUNIT_ASSERT(!s1.encrypt(plaintext, encrypted));
	CPPUNIT_ASSERT(!s1.decrypt(encrypted, plaintext));

	// Export the key blobs
	ByteString soPINBlob = s1.getSOPINBlob();
	ByteString userPINBlob = s1.getUserPINBlob();

	// Create a new instance with the exported key blobs
	SecureDataManager s2(soPINBlob, userPINBlob);

	// Check that the key blobs match
	CPPUNIT_ASSERT(s1.getSOPINBlob() == s2.getSOPINBlob());
	CPPUNIT_ASSERT(s1.getUserPINBlob() == s2.getUserPINBlob());

	// Check that it is not possible to set the SO PIN
	CPPUNIT_ASSERT(!s2.setSOPIN(soPIN));

	// Check that it is possible to log in with the SO PIN
	CPPUNIT_ASSERT(s2.loginSO(soPIN));

	// Check that is is now also possible to log in with the user PIN
	CPPUNIT_ASSERT(s2.loginUser(userPIN));

	// Check that encrypting the data results in different ciphertext because of the random IV
	ByteString encrypted2;

	CPPUNIT_ASSERT(s2.encrypt(plaintext, encrypted2));
	CPPUNIT_ASSERT(encrypted != encrypted2);

	// Check that decrypting earlier data can be done with the recreated key
	CPPUNIT_ASSERT(s2.decrypt(encrypted, decrypted));
	CPPUNIT_ASSERT(decrypted == plaintext);

	// Log in with the SO PIN
	CPPUNIT_ASSERT(s2.loginSO(soPIN));

	// Check that the SO PIN can be changed
	CPPUNIT_ASSERT(s2.setSOPIN(newSOPIN));

	// Check that it is no longer possible to log in with the old SO PIN
	CPPUNIT_ASSERT(!s2.loginSO(soPIN));

	// Check that encrypting/decrypting no longer works
	CPPUNIT_ASSERT(!s2.encrypt(plaintext, encrypted));
	CPPUNIT_ASSERT(!s2.decrypt(encrypted, plaintext));

	// Check that the key blobs differ
	CPPUNIT_ASSERT(s1.getSOPINBlob() != s2.getSOPINBlob());

	// Check that it is possible to log in with the new SO PIN
	CPPUNIT_ASSERT(s2.loginSO(newSOPIN));

	// Log in with the user PIN
	CPPUNIT_ASSERT(s2.loginUser(userPIN));

	// Check that it is possible to change the user PIN
	CPPUNIT_ASSERT(s2.setUserPIN(newUserPIN));

	// Check that it is no longer possible to log in with the old user PIN
	CPPUNIT_ASSERT(!s2.loginUser(userPIN));

	// Check that encrypting/decrypting no longer works
	CPPUNIT_ASSERT(!s2.encrypt(plaintext, encrypted));
	CPPUNIT_ASSERT(!s2.decrypt(encrypted, plaintext));

	// Check that it is possible to log in with the new user PIN
	CPPUNIT_ASSERT(s2.loginUser(newUserPIN));

	// Check that encrypting the data results in the different ciphertext because of the random IV
	CPPUNIT_ASSERT(s2.encrypt(plaintext, encrypted2));
	CPPUNIT_ASSERT(encrypted != encrypted2);

	// Check that decrypting earlier data can be done with the recreated key
	CPPUNIT_ASSERT(s2.decrypt(encrypted, decrypted));
	CPPUNIT_ASSERT(decrypted == plaintext);

	// Check that empty plaintext can be handled
	CPPUNIT_ASSERT(s2.encrypt(emptyPlaintext, encrypted));
	CPPUNIT_ASSERT(s2.decrypt(encrypted, decrypted));
	CPPUNIT_ASSERT(decrypted == emptyPlaintext);

	// Check that is is possible to log in with the SO PIN and re-authenticate
	CPPUNIT_ASSERT(s1.loginSO(soPIN));
	CPPUNIT_ASSERT(!s1.reAuthenticateSO(userPIN));
	CPPUNIT_ASSERT(s1.reAuthenticateSO(soPIN));

	// Check that is is possible to log in with the user PIN and re-authenticate
	CPPUNIT_ASSERT(s1.loginUser(userPIN));
	CPPUNIT_ASSERT(!s1.reAuthenticateUser(soPIN));
	CPPUNIT_ASSERT(s1.reAuthenticateUser(userPIN));

	// Check that it is possible to encrypt and decrypt some data
	CPPUNIT_ASSERT(s1.encrypt(plaintext, encrypted));
	CPPUNIT_ASSERT(encrypted != plaintext);

	CPPUNIT_ASSERT(s1.decrypt(encrypted, decrypted));
	CPPUNIT_ASSERT(decrypted == plaintext);
}

