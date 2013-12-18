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
 softhsm-dump.cpp

 This program can be used for dumping SoftHSM v2 object files.
 *****************************************************************************/

#include <config.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <map>
#include <string>
#include <stdexcept>
#include <vector>
#include "tables.h"

// Attribute types on disk
#define BOOLEAN_ATTR		0x1
#define ULONG_ATTR		0x2
#define BYTES_ATTR		0x3
#define ARRAY_ATTR		0x4

// Maximum byte string length (1Gib)
#define MAX_BYTES		0x3fffffff

// Attribute (in an array)
struct Attribute
{
	uint64_t type;
	uint64_t kind;

	uint8_t boolValue;
	uint64_t ulongValue;
	std::vector<uint8_t> bytestrValue;
};

// Read a boolean (in fact unsigned 8 bit long) value
bool readBool(FILE* stream, uint8_t& value)
{
	value = 0;
	fpos_t pos;
	if (fgetpos(stream, &pos) != 0)
	{
		return false;
	}
	uint8_t v;
	if (fread(&v, 1, 1, stream) != 1)
	{
		(void) fsetpos(stream, &pos);
		return false;
	}
	value = v;
	return true;
}

// Read an unsigned 64 bit long value
bool readULong(FILE* stream, uint64_t& value)
{
	value = 0;
	fpos_t pos;
	if (fgetpos(stream, &pos) != 0)
	{
		return false;
	}
	uint8_t v[8];
	if (fread(v, 1, 8, stream) != 8)
	{
		(void) fsetpos(stream, &pos);
		return false;
	}
	for (size_t i = 0; i < 8; i++)
	{
		value <<= 8;
		value += v[i];
	}
	return true;
}

// Read a byte string (aka uint8_t vector) value
bool readBytes(FILE* stream, std::vector<uint8_t>& value)
{
	size_t len = value.size();
	fpos_t pos;
	if (fgetpos(stream, &pos) != 0)
	{
		return false;
	}
	if (fread(&value[0], 1, len, stream) != len)
	{
		(void) fsetpos(stream, &pos);
		return false;
	}
	return true;
}

// Read an array (aka Attribute vector) value
bool readArray(FILE* stream, uint64_t len, std::vector<Attribute>& value)
{
	fpos_t pos;
	if (fgetpos(stream, &pos) != 0)
	{
		return false;
	}
	while (len != 0)
	{
		Attribute attr;

		if (len < 8)
		{
			(void) fsetpos(stream, &pos);
			return false;
		}
		if (!readULong(stream, attr.type))
		{
			(void) fsetpos(stream, &pos);
			return false;
		}
		len -= 8;

		if (len < 8)
		{
			(void) fsetpos(stream, &pos);
			return false;
		}
		if (!readULong(stream, attr.kind))
		{
			(void) fsetpos(stream, &pos);
			return false;
		}
		len -= 8;

		if (attr.kind == BOOLEAN_ATTR)
		{
			if (len < 1)
			{
				(void) fsetpos(stream, &pos);
				return false;
			}
			len -= 1;
			if (!readBool(stream, attr.boolValue))
			{
				(void) fsetpos(stream, &pos);
				return false;
			}
		}
		else if (attr.kind == ULONG_ATTR)
		{
			if (len < 8)
			{
				(void) fsetpos(stream, &pos);
				return false;
			}
			if (!readULong(stream, attr.ulongValue))
			{
				(void) fsetpos(stream, &pos);
				return false;
			}
			len -= 8;
		}
		else if (attr.kind == BYTES_ATTR)
		{
			uint64_t size;
			if (len < 8)
			{
				(void) fsetpos(stream, &pos);
				return false;
			}
			if (!readULong(stream, size))
			{
				(void) fsetpos(stream, &pos);
				return false;
			}
			len -= 8;

			if (len < size)
			{
				(void) fsetpos(stream, &pos);
				return false;
			}
			attr.bytestrValue.resize(size);
			if (!readBytes(stream, attr.bytestrValue))
			{
				(void) fsetpos(stream, &pos);
				return false;
			}
			len -= size;
		}
		else
		{
			(void) fsetpos(stream, &pos);
			return false;
		}

		value.push_back(attr);
	}

	return true;
}

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

// Dump a boolean (in fact unsigned 8 bit long) value
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

// Dump an unsigned 64 bit long vaue
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

// Dump an array (in fact an Attribute vector) value
void dumpArray(const std::vector<Attribute>& value)
{
	for (std::vector<Attribute>::const_iterator attr = value.begin();
	     attr != value.end();
	     ++attr)
	{
		dumpULong(attr->type, true);
		if ((uint64_t)((uint32_t)attr->type) != attr->type)
		{
			printf("overflow attribute type\n");
		}
		else
		{
			dumpCKA((unsigned long) attr->type, 47);
			printf("\n");
		}

		dumpULong(attr->kind, true);
		if (attr->kind == BOOLEAN_ATTR)
		{
			printf("boolean attribute\n");
			dumpBool(attr->boolValue, true);
			printf("\n");
		}
		else if (attr->kind == ULONG_ATTR)
		{
			printf("unsigned long attribute\n");
			dumpULong(attr->ulongValue, true);
			dumpCKx(attr->type, attr->ulongValue, 47);
			printf("\n");
		}
		else if (attr->kind == BYTES_ATTR)
		{
			printf("byte string attribute\n");
			uint32_t size = attr->bytestrValue.size();
			dumpULong(size, true);
			printf("(length %lu)\n", (unsigned long) size);
			dumpBytes(attr->bytestrValue, true);
		}
		else
		{
			printf("unknown attribute format\n");
		}
	}
}

// Error case
void corrupt(FILE* stream)
{
	uint8_t v;
	for (size_t i = 0; i < 8; i++)
	{
		if (fread(&v, 1, 1, stream) != 1)
		{
			if (ferror(stream))
			{
				printf("get an error...\n");
			}
			return;
		}
		if (i != 0)
		{
			printf(" ");
		}
		printf("%02hhx", v);
	}
	if (fread(&v, 1, 1, stream) != 1)
	{
		if (ferror(stream))
		{
			printf("\nget an error...\n");
		}
		return;
	}
	printf("...\n");
}

// Core function
void dump(FILE* stream)
{
	uint64_t gen;
	if (!readULong(stream, gen))
	{
		if (feof(stream))
		{
			printf("empty file\n");
		}
		else
		{
			corrupt(stream);
		}
		return;
	}
	dumpULong(gen);
	printf("generation %lu\n", (unsigned long) gen);

	while (!feof(stream))
	{
		uint64_t p11type;
		if (!readULong(stream, p11type))
		{
			corrupt(stream);
			return;
		}
		dumpULong(p11type);
		if ((uint64_t)((uint32_t)p11type) != p11type)
		{
			printf("overflow attribute type\n");
		}
		else
		{
			dumpCKA((unsigned long) p11type, 48);
			printf("\n");
		}

		uint64_t disktype;
		if (!readULong(stream, disktype))
		{
			corrupt(stream);
			return;
		}
		dumpULong(disktype);
		switch (disktype)
		{
		case BOOLEAN_ATTR:
			printf("boolean attribute\n");
			break;
		case ULONG_ATTR:
			printf("unsigned long attribute\n");
			break;
		case BYTES_ATTR:
			printf("byte string attribute\n");
			break;
		case ARRAY_ATTR:
			printf("attribute array attribute\n");
			break;
		default:
			printf("unknown attribute format\n");
			break;
		}

		if (disktype == BOOLEAN_ATTR)
		{
			uint8_t value;
			if (!readBool(stream, value))
			{
				corrupt(stream);
				return;
			}
			dumpBool(value);
			printf("\n");
		}
		else if (disktype == ULONG_ATTR)
		{
			uint64_t value;
			if (!readULong(stream, value))
			{
				corrupt(stream);
				return;
			}
			dumpULong(value);
			dumpCKx(p11type, value, 48);
			printf("\n");
		}
		else if (disktype == BYTES_ATTR)
		{
			uint64_t len;
			if (!readULong(stream, len))
			{
				corrupt(stream);
				return;
			}
			dumpULong(len);
			if (len > MAX_BYTES)
			{
				printf("overflow length...\n");
				return;
			}
			printf("(length %lu)\n", (unsigned long) len);

			std::vector<uint8_t> value((size_t) len);
			if (!readBytes(stream, value))
			{
				corrupt(stream);
				return;
			}
			dumpBytes(value);
		}
		else if (disktype == ARRAY_ATTR)
		{
			uint64_t len;
			if (!readULong(stream, len))
			{
				corrupt(stream);
				return;
			}
			dumpULong(len);
			if (len > MAX_BYTES)
			{
				printf("overflow length...\n");
				return;
			}
			printf("(length %lu)\n", (unsigned long) len);

			std::vector<Attribute> value;
			if (!readArray(stream, len, value))
			{
				corrupt(stream);
				return;
			}
			dumpArray(value);
		}
		else
		{
			corrupt(stream);
			return;
		}
	}
}

// Display the usage
void usage()
{
	printf("SoftHSM dump tool. From SoftHSM v2 object file.\n");
	printf("Usage: softhsm-dump path\n");
}

// The main function
int main(int argc, char* argv[])
{
	FILE* stream;

	if (argc != 2)
	{
		usage();
		exit(0);
	}

	stream = fopen(argv[1], "r");
	if (stream == NULL)
	{
		fprintf(stderr, "can't open object file %s\n", argv[1]);
		exit(0);
	}

	printf("Dump of object file \"%s\"\n", argv[1]);
	dump(stream);
	exit(1);
}
