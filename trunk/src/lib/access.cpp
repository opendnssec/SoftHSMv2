/* $Id$ */

/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
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
 access.cpp

 Implements the access rules.
 *****************************************************************************/

#include "access.h"
#include <stdlib.h>
#include <stdio.h>

// Checks if an action is allowed on a given object type.
//
//                                       Type of session
//  Type of object          R/O Public | R/W Public | R/O User | R/W User | R/W SO
//  ------------------------------------------------------------------------------
//  Public session object       R/W    |     R/W    |    R/W   |    R/W   |   R/W
//  Private session object             |            |    R/W   |    R/W   |
//  Public token object         R/O    |     R/W    |    R/O   |    R/W   |   R/W
//  Private token object               |            |    R/O   |    R/W   |

// Can we do R/O operations?
bool haveRO(CK_STATE sessionState, CK_BBOOL isTokenObject, CK_BBOOL isPrivateObject)
{
	switch (sessionState)
	{
		case CKS_RW_SO_FUNCTIONS:
		case CKS_RW_PUBLIC_SESSION:
		case CKS_RO_PUBLIC_SESSION:
			if (isPrivateObject == CK_FALSE)
			{
				return true;
			}
			else
			{
				return false;
			}
			break;
		case CKS_RW_USER_FUNCTIONS:
		case CKS_RO_USER_FUNCTIONS:
			return true;
			break;
		default:
			break;
	}

	return false;
}

// Can we do R/W operations?
bool haveRW(CK_STATE sessionState, CK_BBOOL isTokenObject, CK_BBOOL isPrivateObject)
{
	switch (sessionState)
	{
		case CKS_RW_SO_FUNCTIONS:
		case CKS_RW_PUBLIC_SESSION:
			if (isPrivateObject == CK_FALSE)
			{
				return true;
			}
			else
			{
				return false;
			}
			break;
		case CKS_RW_USER_FUNCTIONS:
			return true;
			break;
		case CKS_RO_USER_FUNCTIONS:
			if (isTokenObject == CK_FALSE)
			{
				return true;
			}
			else
			{
				return false;
			}
			break;
		case CKS_RO_PUBLIC_SESSION:
			if (isPrivateObject == CK_FALSE && isTokenObject == CK_FALSE)
			{
				return true;
			}
			else
			{
				return false;
			}
			break;
		default:
			break;
	}

	return false;
}
