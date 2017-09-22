/*
 * Copyright (c) 2013 .SE (The Internet Infrastructure Foundation)
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
 common.h

 Common definitions for SoftHSMv2 dump.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_COMMON_H
#define _SOFTHSM_V2_COMMON_H

#include <config.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <map>
#include <set>
#include <string>
#include <stdexcept>
#include <vector>
#include "tables.h"

// Table of attribute types
std::map<unsigned long, std::string> CKA_table;

// Dump an attribute type
void dumpCKA(unsigned long cka, int size)
{
	// Lazy fill
	if (CKA_table.empty())
	{
		fill_CKA_table(CKA_table);
	}
	std::string msg;
	try
	{
		msg = CKA_table.at(cka);
		printf("%.*s", size, msg.c_str());
	}
	catch (const std::out_of_range&)
	{
		if (cka & CKA_VENDOR_DEFINED)
		{
			cka &= ~CKA_VENDOR_DEFINED;
			printf("CKA_VENDOR_DEFINED | 0x%lx", cka);
		}
		else
		{
			printf("unknown 0x%lx", cka);
		}
	}
}

// Table of mechanism types
std::map<unsigned long, std::string> CKM_table;

// Dump a mechanism type
void dumpCKM(unsigned long cka, int size)
{
	// Lazy fill
	if (CKM_table.empty())
	{
		fill_CKM_table(CKM_table);
	}
	std::string msg;
	try
	{
		msg = CKM_table.at(cka);
		printf("%.*s", size, msg.c_str());
	}
	catch (const std::out_of_range&)
	{
		if (cka & CKM_VENDOR_DEFINED)
		{
			cka &= ~CKM_VENDOR_DEFINED;
			printf("CKM_VENDOR_DEFINED | 0x%lx", cka);
		}
		else
		{
			printf("unknown 0x%lx", cka);
		}
	}
}

// Table of object classes
std::map<unsigned long, std::string> CKO_table;

// Dump a object class
void dumpCKO(unsigned long cka, int size)
{
	// Lazy fill
	if (CKO_table.empty())
	{
		fill_CKO_table(CKO_table);
	}
	std::string msg;
	try
	{
		msg = CKO_table.at(cka);
		printf("%.*s", size, msg.c_str());
	}
	catch (const std::out_of_range&)
	{
		if (cka & CKO_VENDOR_DEFINED)
		{
			cka &= ~CKO_VENDOR_DEFINED;
			printf("CKO_VENDOR_DEFINED | 0x%lx", cka);
		}
		else
		{
			printf("unknown 0x%lx", cka);
		}
	}
}

// Table of hw feature types
std::map<unsigned long, std::string> CKH_table;

// Dump a hw feature type
void dumpCKH(unsigned long cka, int size)
{
	// Lazy fill
	if (CKH_table.empty())
	{
		fill_CKH_table(CKH_table);
	}
	std::string msg;
	try
	{
		msg = CKH_table.at(cka);
		printf("%.*s", size, msg.c_str());
	}
	catch (const std::out_of_range&)
	{
		if (cka & CKH_VENDOR_DEFINED)
		{
			cka &= ~CKH_VENDOR_DEFINED;
			printf("CKH_VENDOR_DEFINED | 0x%lx", cka);
		}
		else
		{
			printf("unknown 0x%lx", cka);
		}
	}
}

// Table of key types
std::map<unsigned long, std::string> CKK_table;

// Dump a key type
void dumpCKK(unsigned long cka, int size)
{
	// Lazy fill
	if (CKK_table.empty())
	{
		fill_CKK_table(CKK_table);
	}
	std::string msg;
	try
	{
		msg = CKK_table.at(cka);
		printf("%.*s", size, msg.c_str());
	}
	catch (const std::out_of_range&)
	{
		if (cka & CKK_VENDOR_DEFINED)
		{
			cka &= ~CKK_VENDOR_DEFINED;
			printf("CKK_VENDOR_DEFINED | 0x%lx", cka);
		}
		else
		{
			printf("unknown 0x%lx", cka);
		}
	}
}

// Table of certificate types
std::map<unsigned long, std::string> CKC_table;

// Dump a certificate type
void dumpCKC(unsigned long cka, int size)
{
	// Lazy fill
	if (CKC_table.empty())
	{
		fill_CKC_table(CKC_table);
	}
	std::string msg;
	try
	{
		msg = CKC_table.at(cka);
		printf("%.*s", size, msg.c_str());
	}
	catch (const std::out_of_range&)
	{
		if (cka & CKC_VENDOR_DEFINED)
		{
			cka &= ~CKC_VENDOR_DEFINED;
			printf("CKC_VENDOR_DEFINED | 0x%lx", cka);
		}
		else
		{
			printf("unknown 0x%lx", cka);
		}
	}
}

// Dump a PKCS#11 integer type
void dumpCKx(uint64_t cka, uint64_t value, int size)
{
	if ((uint32_t)value == (uint32_t)~0)
	{
		printf("CK_UNAVAILABLE_INFORMATION");
		return;
	}

	switch ((unsigned long) cka)
	{
	case CKA_CLASS:
		if ((uint64_t)((uint32_t)value) != value)
		{
			printf("overflow object class");
			break;
		}
		dumpCKO((unsigned long) value, size);
		break;
	case CKA_CERTIFICATE_TYPE:
		if ((uint64_t)((uint32_t)value) != value)
		{
			printf("overflow certificate type");
			break;
		}
		dumpCKC((unsigned long) value, size);
		break;
	case CKA_KEY_TYPE:
		if ((uint64_t)((uint32_t)value) != value)
		{
			printf("overflow key type");
			break;
		}
		dumpCKK((unsigned long) value, size);
		break;
	case CKA_KEY_GEN_MECHANISM:
		if ((uint64_t)((uint32_t)value) != value)
		{
			printf("overflow mechanism type");
			break;
		}
		dumpCKM((unsigned long) value, size);
		break;
	case CKA_HW_FEATURE_TYPE:
		if ((uint64_t)((uint32_t)value) != value)
		{
			printf("overflow hw feature type");
			break;
		}
		dumpCKH((unsigned long) value, size);
		break;
	default:
		printf("CK_ULONG %lu(0x%lx)",
		       (unsigned long) value,
		       (unsigned long) value);
		break;
	}
}

// Dump a boolean (in fact unsigned 8 bit long) value, true is 0xff
void dumpBool(uint8_t value, bool inArray = false)
{
	printf("%02hhx                      %s", value, inArray ? " " : "");
	switch (value)
	{
	case 0:
		printf("FALSE");
		break;
	case 0xff:
		printf("TRUE");
		break;
	default:
		printf("(invalid) TRUE");
		break;
	}
}

// Dump a boolean (in fact unsigned 8 bit long) value, true is 1
void dumpBool1(uint8_t value, bool inArray = false)
{
	printf("%02hhx                      %s", value, inArray ? " " : "");
	switch (value)
	{
	case 0:
		printf("FALSE");
		break;
	case 1:
		printf("TRUE");
		break;
	default:
		printf("(invalid) TRUE");
		break;
	}
}

// Dump an unsigned 64 bit long value
void dumpULong(uint64_t value, bool inArray = false)
{
	for (int i = 56; i >= 0; i -= 8)
	{
		uint8_t v;
		v = (value >> i) & 0xff;
		printf("%02hhx ", v);
	}
	if (inArray)
	{
		printf(" ");
	}
}

// Dump an unsigned 32 bit long value
void dumpU32(uint32_t value, bool inArray = false)
{
	for (int i = 24; i >= 0; i -= 8)
	{
		uint8_t v;
		v = (value >> i) & 0xff;
		printf("%02hhx ", v);
	}
	printf("            ");
	if (inArray)
	{
		printf(" ");
	}
}

// Dump a byte string (aka uint8_t vector) value
void dumpBytes(const std::vector<uint8_t>& value, bool inArray = false)
{
	size_t len = value.size();
	size_t i = 0;
	while (i + 8 <= len)
	{
		for (size_t j = 0; j < 8; j++)
		{
			printf("%02hhx ", value[i + j]);
		}
		if (inArray)
		{
			printf(" ");
		}
		printf("<");
		for (size_t j = 0; j < 8; j++)
		{
			uint8_t c = value[i + j];
			if (isgraph((int) c) == 0)
			{
				printf(".");
			}
			else
			{
				printf("%c", (int) c);
			}
		}
		printf(">\n");
		i += 8;
	}
	len -= i;
	if (len == 0)
	{
		return;
	}

	for (size_t j = 0; j < len; j++)
	{
		printf("%02hhx ", value[i + j]);
	}
	for (size_t j = len; j < 8; j++)
	{
		printf("   ");
	}
	if (inArray)
	{
		printf(" ");
	}
	printf("<");
	for (size_t j = 0; j < len; j++)
	{
		uint8_t c = value[i + j];
		if (isgraph((int) c) == 0)
		{
			printf(".");
		}
		else
		{
			printf("%c", (int) c);
		}
	}
	for (size_t j =len; j < 8; j++)
	{
		printf(" ");
	}
	printf(">\n");
}

// Attribute (in an array) template
template<typename T, typename K, typename I>
class AttributeTK
{
public:
	T type;
	K kind;

	uint8_t boolValue;
	I ulongValue;
	std::vector<uint8_t> bytestrValue;
	std::set<I> mechSetValue;

	// Dump an array (in fact an Attribute vector) value
	void dumpType() const;
	void dumpKind() const;
	void dumpBoolValue() const;
	void dumpULongValue(I value) const;
	bool isBoolean() const;
	bool isInteger() const;
	bool isBinary() const;
	bool isMechSet() const;
	void dump() const {
		dumpType();
		if ((sizeof(type) > 4) &&
		    ((uint64_t)((uint32_t)type) != type))
		{
			printf("overflow attribute type\n");
		}
		else
		{
			dumpCKA((unsigned long) type, 47);
			printf("\n");
		}

		dumpKind();
		if (isBoolean())
		{
			printf("boolean attribute\n");
			dumpBoolValue();
			printf("\n");
		}
		else if (isInteger())
		{
			printf("unsigned long attribute\n");
			dumpULongValue(ulongValue);
			dumpCKx(type, ulongValue, 47);
			printf("\n");
		}
		else if (isBinary())
		{
			printf("byte string attribute\n");
			I size = bytestrValue.size();
			dumpULongValue(size);
			printf("(length %lu)\n", (unsigned long) size);
			dumpBytes(bytestrValue, true);
		}
		else if (isMechSet())
		{
			printf("mechanism set attribute\n");
			I size = mechSetValue.size();
			dumpULongValue(size);
			printf("(length %lu)\n", (unsigned long) size);
			for (typename std::set<I>::const_iterator i = mechSetValue.begin(); i != mechSetValue.end(); ++i)
			{
                                dumpULongValue(*i);
                                dumpCKM(*i, 47);
                                printf("\n");
                        }
		}
		else
		{
			printf("unknown attribute format\n");
		}
	}
};

#endif // !_SOFTHSM_V2_COMMON_H
