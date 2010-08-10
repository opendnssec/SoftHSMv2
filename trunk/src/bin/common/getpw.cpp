/* $Id$ */

/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation).
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
 getpw.cpp

 Helper function to get a password from the user
 *****************************************************************************/

#include <config.h>
#include "getpw.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Get a password from the user
void getPW(char *pin, char *newPIN, CK_ULONG userType)
{
	// Keep a copy of the PIN because getpass/getpassphrase 
	// will overwrite the previous PIN.
	char password[MAX_PIN_LEN+1];

	int length = 0;

	if (pin)
	{
		length = strlen(pin);
	}

	while (length < MIN_PIN_LEN || length > MAX_PIN_LEN)
	{
		if (userType == CKU_SO)
		{
			printf("*** SO PIN (%i-%i characters) ***\n",
				MIN_PIN_LEN, MAX_PIN_LEN); 
		}
		else
		{
			printf("*** User PIN (%i-%i characters) ***\n",
				MIN_PIN_LEN, MAX_PIN_LEN); 
		}

#ifdef HAVE_GETPASSPHRASE
		if (userType == CKU_SO)
		{
			pin = getpassphrase("Please enter SO PIN: ");
		}
		else
		{
			pin = getpassphrase("Please enter user PIN: ");
		}
#else
		if (userType == CKU_SO)
		{
			pin = getpass("Please enter SO PIN: ");
		}
		else
		{
			pin = getpass("Please enter user PIN: ");
		}
#endif

		length = strlen(pin);
		if (length < MIN_PIN_LEN || length > MAX_PIN_LEN)
		{
			fprintf(stderr, "ERROR: The length of the PIN is out of range.\n");
			length = 0;
			continue;
		}
		strcpy(password, pin);

#ifdef HAVE_GETPASSPHRASE
		if (userType == CKU_SO)
		{
			pin = getpassphrase("Please reenter SO PIN: ");
		}
		else
		{
			pin = getpassphrase("Please reenter user PIN: ");
		}
#else
		if (userType == CKU_SO)
		{
			pin = getpass("Please reenter SO PIN: ");
		}
		else
		{
			pin = getpass("Please reenter user PIN: ");
		}
#endif

		if (strcmp(password, pin))
		{
			fprintf(stderr, "ERROR: The entered PINs are not equal.\n");
			length = 0;
			continue;
		}
	}

	strcpy(newPIN, pin);
}
