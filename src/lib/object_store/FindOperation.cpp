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
 FindOperation.cpp

 This class represents the find operation that can be used to collect
 objects that match the attributes contained in a given template.
 *****************************************************************************/

#include "config.h"
#include "FindOperation.h"

FindOperation::FindOperation()
{
}

FindOperation *FindOperation::create()
{
    return new FindOperation();
}

void FindOperation::recycle()
{
    delete this;
}

void FindOperation::setHandles(const std::set<CK_OBJECT_HANDLE> &handles)
{
    _handles = handles;
}

CK_ULONG FindOperation::retrieveHandles(CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulCount)
{
    CK_ULONG ulReturn = 0;
    std::set<CK_OBJECT_HANDLE>::const_iterator it;
    for (it=_handles.begin(); it != _handles.end(); ++it) {
        if (ulReturn >= ulCount) break;

        phObject[ulReturn++] = *it;
    }
    return ulReturn;
}

CK_ULONG FindOperation::eraseHandles(CK_ULONG ulIndex, CK_ULONG ulCount)
{
    std::set<CK_OBJECT_HANDLE>::const_iterator it;
    for (it=_handles.begin(); it != _handles.end() && ulIndex != 0; --ulIndex) {
        ++it;
    }

    CK_ULONG ulReturn = 0;
    for ( ; it != _handles.end() && ulReturn < ulCount; ++ulReturn) {
        _handles.erase(it++);
    }
    return ulReturn;
}
