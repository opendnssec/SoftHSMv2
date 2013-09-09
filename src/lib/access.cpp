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

// Checks if a read operation is allowed on a given object type.
//
//                                             Type of session
//  Type of object          R/O Public | R/W Public | R/O User | R/W User | R/W SO
//  ------------------------------------------------------------------------------
//  Public session object       OK     |     OK     |    OK    |    OK    |   OK
//  Private session object      UNLI   |     UNLI   |    OK    |    OK    |   UNLI
//  Public token object         OK     |     OK     |    OK    |    OK    |   OK
//  Private token object        UNLI   |     UNLI   |    OK    |    OK    |   UNLI
//
// OK = CKR_OK
// SRO = CKR_SESSION_READ_ONLY
// UNLI = CKR_USER_NOT_LOGGED_IN

// Can we do read operations?
CK_RV haveRead(CK_STATE sessionState, CK_BBOOL /*isTokenObject*/, CK_BBOOL isPrivateObject)
{
	switch (sessionState)
	{
        case CKS_RO_PUBLIC_SESSION:
        case CKS_RW_PUBLIC_SESSION:
        case CKS_RW_SO_FUNCTIONS:
            return isPrivateObject ? CKR_USER_NOT_LOGGED_IN : CKR_OK;
        case CKS_RO_USER_FUNCTIONS:
        case CKS_RW_USER_FUNCTIONS:
            return CKR_OK;
    }
    return CKR_GENERAL_ERROR; // internal error, switch should have covered every state
}

// Checks if a write operation is allowed on a given object type.
//
//                                             Type of session
//  Type of object          R/O Public | R/W Public | R/O User | R/W User | R/W SO
//  ------------------------------------------------------------------------------
//  Public session object       OK     |     OK     |    OK    |    OK    |   OK
//  Private session object      UNLI   |     UNLI   |    OK    |    OK    |   UNLI
//  Public token object         SRO    |     OK     |    SRO   |    OK    |   OK
//  Private token object      SRO/UNLI |     UNLI   |    SRO   |    OK    |   UNLI
//
// OK = CKR_OK
// SRO = CKR_SESSION_READ_ONLY
// UNLI = CKR_USER_NOT_LOGGED_IN
// In the situation where both SRO and UNLI may be returned we favor SRO.

// Can we do write operations?
CK_RV haveWrite(CK_STATE sessionState, CK_BBOOL isTokenObject, CK_BBOOL isPrivateObject)
{
	switch (sessionState)
	{
        case CKS_RO_PUBLIC_SESSION:
            if (isTokenObject)
                return CKR_SESSION_READ_ONLY;
            else
                return isPrivateObject ? CKR_USER_NOT_LOGGED_IN : CKR_OK;
        case CKS_RW_PUBLIC_SESSION:
        case CKS_RW_SO_FUNCTIONS:
            return isPrivateObject ? CKR_USER_NOT_LOGGED_IN : CKR_OK;
        case CKS_RO_USER_FUNCTIONS:
            return isTokenObject ? CKR_SESSION_READ_ONLY : CKR_OK;
        case CKS_RW_USER_FUNCTIONS:
            return CKR_OK;
	}
    return CKR_GENERAL_ERROR; // internal error, switch should have covered every state
}
