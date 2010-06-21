/* $Id$ */

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
 UUID.cpp

 UUID generation helper functions; for now, this just wraps the OSF/DCE's
 UUID generation implementation, but if SoftHSM gets ported to non UNIX/BSD-
 like OSes this may incorporate other implementations
 *****************************************************************************/

#include "config.h"
#include "UUID.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <uuid/uuid.h>

// Generate a new GUID string
std::string UUID::newGUID()
{
#ifdef HAVE_OSFDCE_UUID
	uuid_t newUUID;

	// Generate a new UUID
	uuid_generate(newUUID);

	// Convert it to a string
	char uuidStr[37];

	sprintf(uuidStr, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		newUUID[0], newUUID[1], newUUID[2], newUUID[3], 
		newUUID[4], newUUID[5], 
		newUUID[6], newUUID[7],
		newUUID[8], newUUID[9],
		newUUID[10], newUUID[11], newUUID[12], newUUID[13], newUUID[14], newUUID[15]);

	return std::string(uuidStr);
#else
	#error "There is no UUID generation code for your platform!"
#endif
}

