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
 FindOperation.h

 This class represents the find operation that can be used to collect
 objects that match the attributes contained in a given template.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_FINDOPERATION_H
#define _SOFTHSM_V2_FINDOPERATION_H

#include "config.h"

#include <set>
#include "OSObject.h"

class FindOperation
{
public:
    // Factory method creates a new find operation
    static FindOperation* create();

    // Hand this operation back to the factory for recycling.
    void recycle();

    // Add the objects from thet set that match the attributes in the given template to the find operation.
    void setHandles(const std::set<CK_OBJECT_HANDLE> &handles);

    // Retrieve handles
    CK_ULONG retrieveHandles(CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulCount);

    // Erase handles from the handles set.
    CK_ULONG eraseHandles(CK_ULONG ulIndex, CK_ULONG ulCount);

protected:
    // Use a protected constructor to force creation via factory method.
    FindOperation();

    std::set<CK_OBJECT_HANDLE> _handles;
};

#endif // _SOFTHSM_V2_FINDOPERATION_H
