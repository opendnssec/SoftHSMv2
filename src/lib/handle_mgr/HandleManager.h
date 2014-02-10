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
 HandleManager.h

 Keeps track of the issued cryptoki handles within SoftHSM
 *****************************************************************************/

#ifndef _SOFTHSM_V2_HANDLEMANAGER_H
#define _SOFTHSM_V2_HANDLEMANAGER_H

#include "MutexFactory.h"
#include "Handle.h"
#include "cryptoki.h"

#include <map>

#define CK_INTERNAL_SESSION_HANDLE CK_SESSION_HANDLE

class HandleManager
{
public:
    HandleManager();

    virtual ~HandleManager();

    CK_SESSION_HANDLE addSession(CK_SLOT_ID slotID, CK_VOID_PTR session);
    CK_VOID_PTR getSession(const CK_SESSION_HANDLE hSession);

    // Add the session object and return a handle. For objects that have already been registered, check that the
    // slotID matches. The hSession may be different as the object may be added as part of a find objects operation.
    CK_OBJECT_HANDLE addSessionObject(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession, bool isPrivate, CK_VOID_PTR object);

    // Add the token object and return a handle. For objects that have already been registered, check that the
    // slotID mathces.
    CK_OBJECT_HANDLE addTokenObject(CK_SLOT_ID slotID, bool isPrivate, CK_VOID_PTR object);

    // Get the object pointer associated with the given object handle.
    CK_VOID_PTR getObject(const CK_OBJECT_HANDLE hObject);

    // Get the object handle for the object pointer that has been previously registered.
    // When the object is not found CK_INVALID_HANDLE is returned.
    CK_OBJECT_HANDLE getObjectHandle(CK_VOID_PTR object);

    // Remove the given object handle.
    void destroyObject(const CK_OBJECT_HANDLE hObject);

    // Remove the given session handle and all session object handles for the session.
    // The token object handles retrieved using the session will remain valid unless
    // this is the last session of a token being closed. In that case remove all token
    // object handles for the slot/token associated with the session.
    void sessionClosed(const CK_SESSION_HANDLE hSession);

    // Remove all session and object handles for the given slotID.
    // All handles for the given slotID will become invalid.
    void allSessionsClosed(const CK_SLOT_ID slotID);

    // Remove all handles to private objects for the given slotID.
    // All handles to public objects for the given slotID remain valid.
    void tokenLoggedOut(const CK_SLOT_ID slotID);

private:
    Mutex* handlesMutex;
    std::map< CK_ULONG, Handle> handles;
    std::map< CK_VOID_PTR, CK_ULONG> objects;
    CK_ULONG handleCounter;
};

#endif // !_SOFTHSM_V2_HANDLEMANAGER_H

