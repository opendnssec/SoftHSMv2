/*
 * Copyright (c) 2016 SURFnet bv
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
 findslot.cpp

 Helper function to find the slot
 *****************************************************************************/

#include <config.h>
#include "findslot.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern CK_FUNCTION_LIST_PTR p11;

// Find the slot/token
int findSlot(char* slot, char* serial, char* token, bool freeToken, CK_SLOT_ID& slotID)
{
	if (slot != NULL)
	{
		int slotNumber = atoi(slot);
		if (slotNumber < 0)
		{
			fprintf(stderr, "ERROR: The slot number is negative.\n");
			return 1;
		}

		slotID = slotNumber;
		return 0;
	}

	if (serial == NULL && token == NULL && freeToken == false)
 	{
		fprintf(stderr, "ERROR: A slot/token must be supplied. "
				"Use --slot <number>, --serial <serial>, "
				"--token <label>, or --free\n");
		return 1;
	}

	// Load the variables
	CK_UTF8CHAR paddedSerial[16];
	CK_UTF8CHAR paddedToken[32];
	if (serial != NULL)
	{
		size_t inSize = strlen(serial);
		size_t outSize = sizeof(paddedSerial);
		if (inSize > outSize)
		{
			fprintf(stderr, "ERROR: --serial is too long.\n");
			return 1;
		}
		memset(paddedSerial, ' ', outSize);
		memcpy(paddedSerial, serial, inSize);
	}
	if (token != NULL)
	{
		size_t inSize = strlen(token);
		size_t outSize = sizeof(paddedToken);
		if (inSize > outSize)
		{
			fprintf(stderr, "ERROR: --token is too long.\n");
			return 1;
		}
		memset(paddedToken, ' ', outSize);
		memcpy(paddedToken, token, inSize);
	}

	CK_ULONG ulSlotCount;
	CK_RV rv = p11->C_GetSlotList(CK_TRUE, NULL_PTR, &ulSlotCount);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not get the number of slots.\n");
		return 1;
	}

	CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR) malloc(ulSlotCount*sizeof(CK_SLOT_ID));
	if (pSlotList == NULL)
	{
		fprintf(stderr, "ERROR: Could not allocate memory.\n");
		return 1;
	}

	rv = p11->C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not get the slot list.\n");
		free(pSlotList);
		return 1;
	}

	size_t counter = 0;
	for (CK_ULONG i = 0; i < ulSlotCount; i++)
	{
		CK_TOKEN_INFO tokenInfo;

		rv = p11->C_GetTokenInfo(pSlotList[i], &tokenInfo);
		if (rv != CKR_OK)
		{
			fprintf(stderr, "ERROR: Could not get info about the token in slot %lu.\n",
				pSlotList[i]);
			free(pSlotList);
			return 1;
		}

		if (freeToken)
		{
			if ((tokenInfo.flags & CKF_TOKEN_INITIALIZED) == 0)
			{
				printf("Slot %lu has a free/uninitialized token.\n", pSlotList[i]);
				slotID = pSlotList[i];
				free(pSlotList);
				return 0;
			}
		}
		else
		{
			if (serial != NULL && token == NULL &&
				memcmp(tokenInfo.serialNumber, paddedSerial, sizeof(paddedSerial)) == 0)
			{
				printf("Found slot %lu with matching serial.\n",
				       pSlotList[i]);
				slotID = pSlotList[i];
				counter++;
			}
			if (serial == NULL && token != NULL &&
				memcmp(tokenInfo.label, paddedToken, sizeof(paddedToken)) == 0)
			{
				printf("Found slot %lu with matching token label.\n",
				       pSlotList[i]);
				slotID = pSlotList[i];
				counter++;
			}
			if (serial != NULL && token != NULL &&
				memcmp(tokenInfo.serialNumber, paddedSerial, sizeof(paddedSerial)) == 0 &&
				memcmp(tokenInfo.label, paddedToken, sizeof(paddedToken)) == 0)
			{
				printf("Found slot %lu with matching serial and token label.\n",
				       pSlotList[i]);
				slotID = pSlotList[i];
				counter++;
			}
		}
	}

	free(pSlotList);

	if (counter == 1) return 0;
	if (counter > 1)
	{
		fprintf(stderr, "ERROR: Found multiple matching slots/tokens.\n");
		return 1;
	}

	fprintf(stderr, "ERROR: Could not find a slot/token using --serial, --token, or --free.\n");
	return 1;
}

// Find the slot/token
int findSlot(char* slot, char* serial, char* token, CK_SLOT_ID& slotID)
{
	if (slot != NULL)
	{
		int slotNumber = atoi(slot);
		if (slotNumber < 0)
		{
			fprintf(stderr, "ERROR: The slot number is negative.\n");
			return 1;
		}

		slotID = slotNumber;
		return 0;
	}

	if (serial == NULL && token == NULL)
 	{
		fprintf(stderr, "ERROR: A slot/token must be supplied. "
				"Use --slot <number>, --serial <serial>, "
				"or --token <label>\n");
		return 1;
	}

	// Load the variables
	CK_UTF8CHAR paddedSerial[16];
	CK_UTF8CHAR paddedToken[32];
	if (serial != NULL)
	{
		size_t inSize = strlen(serial);
		size_t outSize = sizeof(paddedSerial);
		if (inSize > outSize)
		{
			fprintf(stderr, "ERROR: --serial is too long.\n");
			return 1;
		}
		memset(paddedSerial, ' ', outSize);
		memcpy(paddedSerial, serial, inSize);
	}
	if (token != NULL)
	{
		size_t inSize = strlen(token);
		size_t outSize = sizeof(paddedToken);
		if (inSize > outSize)
		{
			fprintf(stderr, "ERROR: --token is too long.\n");
			return 1;
		}
		memset(paddedToken, ' ', outSize);
		memcpy(paddedToken, token, inSize);
	}

	CK_ULONG ulSlotCount;
	CK_RV rv = p11->C_GetSlotList(CK_TRUE, NULL_PTR, &ulSlotCount);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not get the number of slots.\n");
		return 1;
	}

	CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR) malloc(ulSlotCount*sizeof(CK_SLOT_ID));
	if (pSlotList == NULL)
	{
		fprintf(stderr, "ERROR: Could not allocate memory.\n");
		return 1;
	}

	rv = p11->C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not get the slot list.\n");
		free(pSlotList);
		return 1;
	}

	size_t counter = 0;
	for (CK_ULONG i = 0; i < ulSlotCount; i++)
	{
		CK_TOKEN_INFO tokenInfo;

		rv = p11->C_GetTokenInfo(pSlotList[i], &tokenInfo);
		if (rv != CKR_OK)
		{
			fprintf(stderr, "ERROR: Could not get info about the token in slot %lu.\n",
				pSlotList[i]);
			free(pSlotList);
			return 1;
		}

		if (serial != NULL && token == NULL &&
			memcmp(tokenInfo.serialNumber, paddedSerial, sizeof(paddedSerial)) == 0)
		{
			printf("Found slot %lu with matching serial.\n",
			       pSlotList[i]);
			slotID = pSlotList[i];
			counter++;
		}
		if (serial == NULL && token != NULL &&
			memcmp(tokenInfo.label, paddedToken, sizeof(paddedToken)) == 0)
		{
			printf("Found slot %lu with matching token label.\n",
			       pSlotList[i]);
			slotID = pSlotList[i];
			counter++;
		}
		if (serial != NULL && token != NULL &&
			memcmp(tokenInfo.serialNumber, paddedSerial, sizeof(paddedSerial)) == 0 &&
			memcmp(tokenInfo.label, paddedToken, sizeof(paddedToken)) == 0)
		{
			printf("Found slot %lu with matching serial and token label.\n",
			       pSlotList[i]);
			slotID = pSlotList[i];
			counter++;
		}
	}

	free(pSlotList);

	if (counter == 1) return 0;
	if (counter > 1)
	{
		fprintf(stderr, "ERROR: Found multiple matching slots/tokens.\n");
		return 1;
	}

	fprintf(stderr, "ERROR: Could not find a slot/token using --serial, or --token\n");
	return 1;
}

// Find the slot/token
int findSlot(CK_TOKEN_INFO tokenInfo, CK_SLOT_ID& slotID)
{
	CK_ULONG ulSlotCount;
	CK_RV rv = p11->C_GetSlotList(CK_TRUE, NULL_PTR, &ulSlotCount);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not get the number of slots.\n");
		return 1;
	}

	CK_SLOT_ID_PTR pSlotList = (CK_SLOT_ID_PTR) malloc(ulSlotCount*sizeof(CK_SLOT_ID));
	if (pSlotList == NULL)
	{
		fprintf(stderr, "ERROR: Could not allocate memory.\n");
		return 1;
	}

	rv = p11->C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not get the slot list.\n");
		free(pSlotList);
		return 1;
	}

	size_t counter = 0;
	for (CK_ULONG i = 0; i < ulSlotCount; i++)
	{
		CK_TOKEN_INFO currentTokenInfo;

		rv = p11->C_GetTokenInfo(pSlotList[i], &currentTokenInfo);
		if (rv != CKR_OK)
		{
			fprintf(stderr, "ERROR: Could not get info about the token in slot %lu.\n",
				pSlotList[i]);
			free(pSlotList);
			return 1;
		}

		if (memcmp(currentTokenInfo.serialNumber, tokenInfo.serialNumber, sizeof(tokenInfo.serialNumber)) == 0 &&
		    memcmp(currentTokenInfo.label, tokenInfo.label, sizeof(tokenInfo.label)) == 0)
		{
			slotID = pSlotList[i];
			counter++;
		}
	}

	free(pSlotList);

	if (counter == 1) return 0;
	if (counter > 1)
	{
		fprintf(stderr, "ERROR: Found multiple matching slots/tokens.\n");
		return 1;
	}

	fprintf(stderr, "ERROR: Could not find a slot/token using --serial, or --token\n");
	return 1;
}
