/*
 * Copyright (c) 2011 .SE (The Internet Infrastructure Foundation)
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
 P11Attributes.h

 This file contains classes for controlling attributes
 *****************************************************************************/

#ifndef _SOFTHSM_V2_P11ATTRIBUTES_H
#define _SOFTHSM_V2_P11ATTRIBUTES_H

#include "cryptoki.h"
#include "OSObject.h"
#include "Token.h"

// The operation types
#define OBJECT_OP_NONE		0x0
#define OBJECT_OP_COPY		0x1
#define OBJECT_OP_CREATE	0x2
#define OBJECT_OP_DERIVE	0x3
#define OBJECT_OP_GENERATE	0x4
#define OBJECT_OP_SET		0x5
#define OBJECT_OP_UNWRAP	0x6

class P11Attribute
{
public:
	// Destructor
	virtual ~P11Attribute();

	// Initialize the attribute
	bool init();

	// Return the attribute type
	CK_ATTRIBUTE_TYPE getType();

	// Retrieve the value if allowed
	CK_RV retrieve(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG_PTR pulValueLen);

	// Update the value if allowed
	CK_RV update(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);

	// Checks are determined by footnotes from table 15 on page 62 in the PKCS#11 v2.3 spec.
	// Table 15 contains common footnotes for object attribute tables that determine the checks to perform on attributes.
	// There are also checks not in table 15 that have been added here to allow enforcing additional contraints.
	enum {
		ck1=1,          //  1  Must be specified when object is created with C_CreateObject.
		ck2=2,          //  2  Must not be specified when object is created with C_CreateObject.
		ck3=4,          //  3  Must be specified when object is generated with C_GenerateKey or C_GenerateKeyPair.
		ck4=8,          //  4  Must not be specified when object is generated with C_GenerateKey or C_GenerateKeyPair.
		ck5=0x10,       //  5  Must be specified when object is unwrapped with C_UnwrapKey.
		ck6=0x20,       //  6  Must not be specified when object is unwrapped with C_UnwrapKey.
		ck7=0x40,       //  7  Cannot be revealed if object has its CKA_SENSITIVE attribute set to CK_TRUE or
						//      its CKA_EXTRACTABLE attribute set to CK_FALSE.
		ck8=0x80,       //  8  May be modified after object is created with a C_SetAttributeValue call
						//      or in the process of copying an object with a C_CopyObject call.
						//      However, it is possible that a particular token may not permit modification of
						//      the attribute during the course of a C_CopyObject call.
		ck9=0x100,      //  9  Default value is token-specific, and may depend on the values of other attributes.
		ck10=0x200,     // 10  Can only be set to CK_TRUE by the SO user.
		ck11=0x400,     // 11  Attribute cannot be changed once set to CK_TRUE. It becomes a read only attribute.
		ck12=0x800,     // 12  Attribute cannot be changed once set to CK_FALSE. It becomes a read only attribute.
		ck13=0x1000,    // Intentionally not defined
		ck14=0x2000,    // 14  Must be non-empty if CKA_URL is empty (CKA_VALUE)
		ck15=0x4000,    // 15  Must be non-empty if CKA_VALUE is empty (CKA_URL)
		ck16=0x8000,    // 16  Can only be empty if CKA_URL is empty
		ck17=0x10000,   // 17  Can be changed in the process of copying the object using C_CopyObject.
		ck18=0x20000,
		ck19=0x40000,
		ck20=0x80000,
		ck21=0x100000,
		ck22=0x200000,
		ck23=0x400000,
		ck24=0x800000
	};
protected:
	// Constructor
	P11Attribute(OSObject* osobject);

	// The object
	OSObject* osobject;

	// The attribute type
	CK_ATTRIBUTE_TYPE type;

	// The checks to perform when the attribute is accessed.
	CK_ULONG checks;

	// The attribute fixed size contains (CK_ULONG)-1 when size is variable.
	CK_ULONG size;

	// Set the default value of the attribute
	virtual bool setDefault() = 0;

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);

	// Helper functions
	bool isModifiable();
	bool isSensitive();
	bool isExtractable();
	bool isTrusted();
};

/*****************************************
 * CKA_CLASS
 *****************************************/

class P11AttrClass : public P11Attribute
{
public:
	// Constructor
	P11AttrClass(OSObject* osobject) : P11Attribute(osobject) { type = CKA_CLASS; size = sizeof(CK_OBJECT_CLASS); checks = ck1; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_KEY_TYPE
 *****************************************/

class P11AttrKeyType : public P11Attribute
{
public:
	// Constructor
	P11AttrKeyType(OSObject* osobject) : P11Attribute(osobject) { type = CKA_KEY_TYPE; size = sizeof(CK_KEY_TYPE); checks = ck1|ck5; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_CERTIFICATE_TYPE
 *****************************************/

class P11AttrCertificateType : public P11Attribute
{
public:
	// Constructor
	P11AttrCertificateType(OSObject* osobject) : P11Attribute(osobject) { type = CKA_CERTIFICATE_TYPE; size = sizeof(CK_CERTIFICATE_TYPE); checks = ck1; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_TOKEN
 *****************************************/

class P11AttrToken : public P11Attribute
{
public:
	// Constructor
	P11AttrToken(OSObject* osobject) : P11Attribute(osobject) { type = CKA_TOKEN; size = sizeof(CK_BBOOL); checks = ck17; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_PRIVATE
 *****************************************/

class P11AttrPrivate : public P11Attribute
{
public:
	// Constructor
	P11AttrPrivate(OSObject* osobject) : P11Attribute(osobject) { type = CKA_PRIVATE; size = sizeof(CK_BBOOL); checks = ck17; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_MODIFIABLE
 *****************************************/

class P11AttrModifiable : public P11Attribute
{
public:
	// Constructor
	P11AttrModifiable(OSObject* osobject) : P11Attribute(osobject) { type = CKA_MODIFIABLE; size = sizeof(CK_BBOOL); checks = ck17; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_LABEL
 *****************************************/

class P11AttrLabel : public P11Attribute
{
public:
	// Constructor
	P11AttrLabel(OSObject* osobject) : P11Attribute(osobject) { type = CKA_LABEL;  checks = ck8; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_COPYABLE
 *****************************************/

class P11AttrCopyable : public P11Attribute
{
public:
	// Constructor
	P11AttrCopyable(OSObject* osobject) : P11Attribute(osobject) { type = CKA_COPYABLE; size = sizeof(CK_BBOOL); checks = ck12; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_APPLICATION
 *****************************************/

class P11AttrApplication : public P11Attribute
{
public:
	// Constructor
	P11AttrApplication(OSObject* osobject) : P11Attribute(osobject) { type = CKA_APPLICATION; checks = 0; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_OBJECT_ID
 *****************************************/

class P11AttrObjectID : public P11Attribute
{
public:
	// Constructor
	P11AttrObjectID(OSObject* osobject) : P11Attribute(osobject) { type = CKA_OBJECT_ID; checks = 0; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_CHECK_VALUE
 *****************************************/

class P11AttrCheckValue : public P11Attribute
{
public:
	// Constructor
	P11AttrCheckValue(OSObject* osobject) : P11Attribute(osobject) { type = CKA_CHECK_VALUE; checks = 0; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_ID
 *****************************************/

class P11AttrID : public P11Attribute
{
public:
	// Constructor
	P11AttrID(OSObject* osobject) : P11Attribute(osobject) { type = CKA_ID; checks = ck8; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_VALUE
 *****************************************/

class P11AttrValue : public P11Attribute
{
public:
	// Constructor
	P11AttrValue(OSObject* osobject, CK_ULONG inchecks) : P11Attribute(osobject) { type = CKA_VALUE; checks = inchecks; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_SUBJECT
 *****************************************/

class P11AttrSubject : public P11Attribute
{
public:
	// Constructor
	P11AttrSubject(OSObject* osobject, CK_ULONG inchecks) : P11Attribute(osobject) { type = CKA_SUBJECT; checks = inchecks; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_ISSUER
 *****************************************/

class P11AttrIssuer : public P11Attribute
{
public:
	// Constructor
	P11AttrIssuer(OSObject* osobject) : P11Attribute(osobject) { type = CKA_ISSUER; checks = ck8; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_TRUSTED
 *****************************************/

class P11AttrTrusted : public P11Attribute
{
public:
	// Constructor
	P11AttrTrusted(OSObject* osobject) : P11Attribute(osobject) { type = CKA_TRUSTED; size = sizeof(CK_BBOOL); checks = ck10; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_CERTIFICATE_CATEGORY
 *****************************************/

class P11AttrCertificateCategory : public P11Attribute
{
public:
	// Constructor
	P11AttrCertificateCategory(OSObject* osobject) : P11Attribute(osobject) { type = CKA_CERTIFICATE_CATEGORY; size = sizeof(CK_ULONG); checks = 0; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_START_DATE
 * Because this attribute is used in a
 * certificate object where the CKA_VALUE
 * containing the certificate data is not
 * modifiable, we assume that this attribute
 * is also not modifiable.
 * There is also no explicit mention of
 * this CKA_START_DATE attribute being
 * modifiable,
 *****************************************/

class P11AttrStartDate : public P11Attribute
{
public:
	// Constructor
	P11AttrStartDate(OSObject* osobject) : P11Attribute(osobject) { type = CKA_START_DATE; checks = 0; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_END_DATE
 * Because this attribute is used in a
 * certificate object where the CKA_VALUE
 * containing the certificate data is not
 * modifiable, we assume that this attribute
 * is also not modifiable.
 * There is also no explicit mention of
 * this CKA_END_DATE attribute being
 * modifiable,
 *****************************************/

class P11AttrEndDate : public P11Attribute
{
public:
	// Constructor
	P11AttrEndDate(OSObject* osobject) : P11Attribute(osobject) { type = CKA_END_DATE; checks = 0; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_SERIAL_NUMBER
 *****************************************/

class P11AttrSerialNumber : public P11Attribute
{
public:
	// Constructor
	P11AttrSerialNumber(OSObject* osobject) : P11Attribute(osobject) { type = CKA_SERIAL_NUMBER; checks = ck8; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_URL
 *****************************************/

class P11AttrURL : public P11Attribute
{
public:
	// Constructor
	P11AttrURL(OSObject* osobject) : P11Attribute(osobject) { type = CKA_URL; checks = ck15; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_HASH_OF_SUBJECT_PUBLIC_KEY
 *****************************************/

class P11AttrHashOfSubjectPublicKey : public P11Attribute
{
public:
	// Constructor
	P11AttrHashOfSubjectPublicKey(OSObject* osobject) : P11Attribute(osobject) { type = CKA_HASH_OF_SUBJECT_PUBLIC_KEY; checks = ck16; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_HASH_OF_ISSUER_PUBLIC_KEY
 *****************************************/

class P11AttrHashOfIssuerPublicKey : public P11Attribute
{
public:
	// Constructor
	P11AttrHashOfIssuerPublicKey(OSObject* osobject) : P11Attribute(osobject) { type = CKA_HASH_OF_ISSUER_PUBLIC_KEY; checks = ck16; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_JAVA_MIDP_SECURITY_DOMAIN
 *****************************************/

class P11AttrJavaMidpSecurityDomain : public P11Attribute
{
public:
	// Constructor
	P11AttrJavaMidpSecurityDomain(OSObject* osobject) : P11Attribute(osobject) { type = CKA_JAVA_MIDP_SECURITY_DOMAIN; size = sizeof(CK_ULONG); checks = 0; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_NAME_HASH_ALGORITHM
 *****************************************/

class P11AttrNameHashAlgorithm : public P11Attribute
{
public:
	// Constructor
	P11AttrNameHashAlgorithm(OSObject* osobject) : P11Attribute(osobject) { type = CKA_NAME_HASH_ALGORITHM; size = sizeof(CK_MECHANISM_TYPE); checks = 0; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_DERIVE
 *****************************************/

class P11AttrDerive : public P11Attribute
{
public:
	// Constructor
	P11AttrDerive(OSObject* osobject) : P11Attribute(osobject) { type = CKA_DERIVE; size = sizeof(CK_BBOOL); checks = ck8;}

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_ENCRYPT
 *****************************************/

class P11AttrEncrypt : public P11Attribute
{
public:
	// Constructor
	P11AttrEncrypt(OSObject* osobject) : P11Attribute(osobject) { type = CKA_ENCRYPT; size = sizeof(CK_BBOOL); checks = ck8|ck9; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_VERIFY
 *****************************************/

class P11AttrVerify : public P11Attribute
{
public:
	// Constructor
	P11AttrVerify(OSObject* osobject) : P11Attribute(osobject) { type = CKA_VERIFY; size = sizeof(CK_BBOOL); checks = ck8|ck9; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_VERIFY_RECOVER
 *****************************************/

class P11AttrVerifyRecover : public P11Attribute
{
public:
	// Constructor
	P11AttrVerifyRecover(OSObject* osobject) : P11Attribute(osobject) { type = CKA_VERIFY_RECOVER; size = sizeof(CK_BBOOL); checks = ck8|ck9; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_WRAP
 *****************************************/

class P11AttrWrap : public P11Attribute
{
public:
	// Constructor
	P11AttrWrap(OSObject* osobject) : P11Attribute(osobject) { type = CKA_WRAP; size = sizeof(CK_BBOOL); checks = ck8|ck9; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_DECRYPT
 *****************************************/

class P11AttrDecrypt : public P11Attribute
{
public:
	// Constructor
	P11AttrDecrypt(OSObject* osobject) : P11Attribute(osobject) { type = CKA_DECRYPT; size = sizeof(CK_BBOOL); checks = ck8|ck9; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_SIGN
 *****************************************/

class P11AttrSign : public P11Attribute
{
public:
	// Constructor
	P11AttrSign(OSObject* osobject) : P11Attribute(osobject) { type = CKA_SIGN; size = sizeof(CK_BBOOL); checks = ck8|ck9; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_SIGN_RECOVER
 *****************************************/

class P11AttrSignRecover : public P11Attribute
{
public:
	// Constructor
	P11AttrSignRecover(OSObject* osobject) : P11Attribute(osobject) { type = CKA_SIGN_RECOVER; size = sizeof(CK_BBOOL); checks = ck8|ck9; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_UNWRAP
 *****************************************/

class P11AttrUnwrap : public P11Attribute
{
public:
	// Constructor
	P11AttrUnwrap(OSObject* osobject) : P11Attribute(osobject) { type = CKA_UNWRAP; size = sizeof(CK_BBOOL); checks = ck8|ck9; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_LOCAL
 *****************************************/

class P11AttrLocal : public P11Attribute
{
public:
	// Constructor
	P11AttrLocal(OSObject* osobject) : P11Attribute(osobject) { type = CKA_LOCAL; size = sizeof(CK_BBOOL); checks = ck2|ck4|ck6; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_KEY_GEN_MECHANISM
 *****************************************/

class P11AttrKeyGenMechanism : public P11Attribute
{
public:
	// Constructor
	P11AttrKeyGenMechanism(OSObject* osobject) : P11Attribute(osobject) { type = CKA_KEY_GEN_MECHANISM; size = sizeof(CK_MECHANISM_TYPE); checks = ck2|ck4|ck6; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_ALWAYS_SENSITIVE
 *****************************************/

class P11AttrAlwaysSensitive : public P11Attribute
{
public:
	// Constructor
	P11AttrAlwaysSensitive(OSObject* osobject) : P11Attribute(osobject) { type = CKA_ALWAYS_SENSITIVE; size = sizeof(CK_BBOOL); checks = ck2|ck4|ck6; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_NEVER_EXTRACTABLE
 *****************************************/

class P11AttrNeverExtractable : public P11Attribute
{
public:
	// Constructor
	P11AttrNeverExtractable(OSObject* osobject) : P11Attribute(osobject) { type = CKA_NEVER_EXTRACTABLE; size = sizeof(CK_BBOOL); checks = ck2|ck4; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_SENSITIVE
 *****************************************/

class P11AttrSensitive : public P11Attribute
{
public:
	// Constructor
	P11AttrSensitive(OSObject* osobject) : P11Attribute(osobject) { type = CKA_SENSITIVE; size = sizeof(CK_BBOOL); checks = ck8|ck9|ck11; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_EXTRACTABLE
 *****************************************/

class P11AttrExtractable : public P11Attribute
{
public:
	// Constructor
	P11AttrExtractable(OSObject* osobject) : P11Attribute(osobject) { type = CKA_EXTRACTABLE; size = sizeof(CK_BBOOL); checks = ck8|ck9|ck12; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_WRAP_WITH_TRUSTED
 *****************************************/

class P11AttrWrapWithTrusted : public P11Attribute
{
public:
	// Constructor
	P11AttrWrapWithTrusted(OSObject* osobject) : P11Attribute(osobject) { type = CKA_WRAP_WITH_TRUSTED; size = sizeof(CK_BBOOL); checks = ck11; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_ALWAYS_AUTHENTICATE
 *****************************************/

class P11AttrAlwaysAuthenticate : public P11Attribute
{
public:
	// Constructor
	P11AttrAlwaysAuthenticate(OSObject* osobject) : P11Attribute(osobject) { type = CKA_ALWAYS_AUTHENTICATE; size = sizeof(CK_BBOOL); checks = 0; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_MODULUS
 *****************************************/

class P11AttrModulus : public P11Attribute
{
public:
	// Constructor
	P11AttrModulus(OSObject* osobject) : P11Attribute(osobject) { type = CKA_MODULUS; checks = ck1|ck4|ck6; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_PUBLIC_EXPONENT
 *****************************************/

class P11AttrPublicExponent : public P11Attribute
{
public:
	// Constructor
	P11AttrPublicExponent(OSObject* osobject, CK_ULONG inchecks) : P11Attribute(osobject) { type = CKA_PUBLIC_EXPONENT; checks = inchecks; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_PRIVATE_EXPONENT
 *****************************************/

class P11AttrPrivateExponent : public P11Attribute
{
public:
	// Constructor
	P11AttrPrivateExponent(OSObject* osobject) : P11Attribute(osobject) { type = CKA_PRIVATE_EXPONENT; checks = ck1|ck4|ck6|ck7; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_PRIME_1
 *****************************************/

class P11AttrPrime1 : public P11Attribute
{
public:
	// Constructor
	P11AttrPrime1(OSObject* osobject) : P11Attribute(osobject) { type = CKA_PRIME_1; checks = ck4|ck6|ck7; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_PRIME_2
 *****************************************/

class P11AttrPrime2 : public P11Attribute
{
public:
	// Constructor
	P11AttrPrime2(OSObject* osobject) : P11Attribute(osobject) { type = CKA_PRIME_2; checks = ck4|ck6|ck7; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_EXPONENT_1
 *****************************************/

class P11AttrExponent1 : public P11Attribute
{
public:
	// Constructor
	P11AttrExponent1(OSObject* osobject) : P11Attribute(osobject) { type = CKA_EXPONENT_1; checks = ck4|ck6|ck7; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_EXPONENT_2
 *****************************************/

class P11AttrExponent2 : public P11Attribute
{
public:
	// Constructor
	P11AttrExponent2(OSObject* osobject) : P11Attribute(osobject) { type = CKA_EXPONENT_2; checks = ck4|ck6|ck7; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_COEFFICIENT
 *****************************************/

class P11AttrCoefficient : public P11Attribute
{
public:
	// Constructor
	P11AttrCoefficient(OSObject* osobject) : P11Attribute(osobject) { type = CKA_COEFFICIENT; checks = ck4|ck6|ck7; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_MODULUS_BITS
 *****************************************/

class P11AttrModulusBits : public P11Attribute
{
public:
	// Constructor
	P11AttrModulusBits(OSObject* osobject) : P11Attribute(osobject) { type = CKA_MODULUS_BITS; size = sizeof(CK_ULONG); checks = ck2|ck3;}

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_PRIME
 *****************************************/

class P11AttrPrime : public P11Attribute
{
public:
	// Constructor
	P11AttrPrime(OSObject* osobject, CK_ULONG inchecks = 0) : P11Attribute(osobject) { type = CKA_PRIME; checks = ck1|inchecks; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_SUBPRIME
 *****************************************/

class P11AttrSubPrime : public P11Attribute
{
public:
	// Constructor
	P11AttrSubPrime(OSObject* osobject, CK_ULONG inchecks = 0) : P11Attribute(osobject) { type = CKA_SUBPRIME; checks = ck1|inchecks; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_BASE
 *****************************************/

class P11AttrBase : public P11Attribute
{
public:
	// Constructor
	P11AttrBase(OSObject* osobject, CK_ULONG inchecks = 0) : P11Attribute(osobject) { type = CKA_BASE; checks = ck1|inchecks; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_PRIME_BITS
 *****************************************/

class P11AttrPrimeBits : public P11Attribute
{
public:
	// Constructor
	P11AttrPrimeBits(OSObject* osobject) : P11Attribute(osobject) { type = CKA_PRIME_BITS; size = sizeof(CK_ULONG); checks = ck2|ck3;}

protected:
	// Set the default value of the attribute
	virtual bool setDefault();

	// Update the value if allowed
	virtual CK_RV updateAttr(Token *token, bool isPrivate, CK_VOID_PTR pValue, CK_ULONG ulValueLen, int op);
};

/*****************************************
 * CKA_EC_PARAMS
 *****************************************/

class P11AttrEcParams : public P11Attribute
{
public:
	// Constructor
	P11AttrEcParams(OSObject* osobject, CK_ULONG inchecks = 0) : P11Attribute(osobject) { type = CKA_EC_PARAMS; checks = ck1|inchecks; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_EC_POINT
 *****************************************/

class P11AttrEcPoint : public P11Attribute
{
public:
	// Constructor
	P11AttrEcPoint(OSObject* osobject) : P11Attribute(osobject) { type = CKA_EC_POINT; checks = ck1|ck4; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_GOSTR3410_PARAMS
 *****************************************/

class P11AttrGostR3410Params : public P11Attribute
{
public:
	// Constructor
	P11AttrGostR3410Params(OSObject* osobject, CK_ULONG inchecks = 0) : P11Attribute(osobject) { type = CKA_GOSTR3410_PARAMS; checks = ck1|inchecks; }

// id-GostR3410-2001-CryptoPro-A-ParamSet 1.2.643.2.2.35.1
#define GostR3419_A_ParamSet	"06072a850302022301"

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_GOSTR3411_PARAMS
 *****************************************/

class P11AttrGostR3411Params : public P11Attribute
{
public:
	// Constructor
	P11AttrGostR3411Params(OSObject* osobject, CK_ULONG inchecks = 0) : P11Attribute(osobject) { type = CKA_GOSTR3411_PARAMS; checks = ck1|ck8|inchecks; }

// id-GostR3411-94-CryptoProParamSet 1.2.643.2.2.30.1
#define GostR3411_ParamSet	"06072a850302021e01"

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

/*****************************************
 * CKA_GOST28147_PARAMS
 *****************************************/

class P11AttrGost28147Params : public P11Attribute
{
public:
	// Constructor
	P11AttrGost28147Params(OSObject* osobject, CK_ULONG inchecks = 0) : P11Attribute(osobject) { type = CKA_GOST28147_PARAMS; checks = ck8|inchecks; }

protected:
	// Set the default value of the attribute
	virtual bool setDefault();
};

#endif // !_SOFTHSM_V2_P11ATTRIBUTES_H
