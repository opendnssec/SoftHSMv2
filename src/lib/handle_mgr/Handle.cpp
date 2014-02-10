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
 Handle.h

 This class represents a single handle
 *****************************************************************************/

#include "Handle.h"

// Constructor
Handle::Handle(CK_HANDLE_KIND _kind, CK_SLOT_ID _slotID, CK_SESSION_HANDLE _hSession)
    : kind(_kind), slotID(_slotID), hSession(_hSession), object(NULL_PTR), isPrivate(false)
{
}

Handle::Handle(CK_HANDLE_KIND _kind, CK_SLOT_ID _slotID)
    : kind(_kind), slotID(_slotID), hSession(CK_INVALID_HANDLE), object(NULL_PTR), isPrivate(false)
{
}

Handle::Handle()
    : kind(CKH_INVALID), slotID(0), hSession(CK_INVALID_HANDLE), object(NULL_PTR), isPrivate(false)
{

}
