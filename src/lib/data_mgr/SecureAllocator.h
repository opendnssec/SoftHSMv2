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
 SecureAllocator.h

 Implements a template class for a secure C++ allocator. The allocator will
 zero all the memory it allocates before releasing it to ensure that the
 data stored in the memory is destroyed properly to minimise the risk of
 obtaining sensitive data from memory
 *****************************************************************************/

#ifndef _SOFTHSM_V2_SECUREALLOCATOR_H
#define _SOFTHSM_V2_SECUREALLOCATOR_H

#include <limits>
#include <stdlib.h>
#include <string.h>
#if defined(SENSITIVE_NON_PAGED) && !defined(_WIN32)
#include <sys/mman.h>
#endif // SENSITIVE_NON_PAGED
#include "config.h"
#include "log.h"
#include "SecureMemoryRegistry.h"

template<class T> class SecureAllocator
{
public:
	// Member types
	typedef T 		value_type;
	typedef T* 		pointer;
	typedef T& 		reference;
	typedef const T*	const_pointer;
	typedef const T&	const_reference;
	typedef size_t		size_type;
	typedef ptrdiff_t	difference_type;

	// Rebind to another type
	template<class U> struct rebind
	{
		typedef SecureAllocator<U> other;
	};

	// Constructor
	inline SecureAllocator() { }

	inline SecureAllocator(const SecureAllocator&) { }

	template<class U> SecureAllocator(const SecureAllocator<U>&) { }

	// Destructor
	inline virtual ~SecureAllocator() { }

	// Return the maximum allocation size
	size_type max_size() const
	{
		return std::numeric_limits<std::size_t>::max() / sizeof(T);
	}

	// Return the address of values
	inline pointer address(reference value) const
	{
		return &value;
	}

	inline const_pointer address(const_reference value) const
	{
		return &value;
	}

	// Allocate n elements of type T
	inline pointer allocate(size_type n, const void* = NULL)
	{
#ifdef SENSITIVE_NON_PAGED
		// Allocate memory on a page boundary
#ifndef _WIN32
		pointer r = (pointer) valloc(n * sizeof(T));
#else
		pointer r = (pointer) VirtualAlloc(NULL, n * sizeof(T), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#endif

		if (r == NULL)
		{
			ERROR_MSG("Out of memory");

			return NULL;
		}

		// Lock the memory so it doesn't get swapped out
#ifndef _WIN32
		if (mlock((const void*) r, n * sizeof(T)) != 0)
#else
		if (VirtualLock((const void*) r, n * sizeof(T)) == 0)
#endif
		{
			ERROR_MSG("Could not allocate non-paged memory for secure storage");

			// Hmmm... best to not return any allocated space in this case
#ifndef _WIN32
			free(r);
#else
			VirtualFree((const void*) r, MEM_RELEASE);
#endif

			return NULL;
		}

		// Register the memory in the secure memory registry
		SecureMemoryRegistry::i()->add(r, n * sizeof(T));

		return r;
#else
		pointer r = (pointer)(::operator new(n * sizeof(T)));

		if (r == NULL)
		{
			ERROR_MSG("Out of memory");

			return NULL;
		}

		// Register the memory in the secure memory registry
		SecureMemoryRegistry::i()->add(r, n * sizeof(T));

		return r;
#endif // SENSITIVE_NON_PAGED
	}

	// Deallocate n elements of type T
	inline void deallocate(pointer p, size_type n)
	{
#ifdef PARANOID
		// First toggle all bits on
		memset(p, 0xFF, n * sizeof(T));
#endif // PARANOID

		// Toggle all bits off
		memset(p, 0x00, n * sizeof(T));

		// Unregister the memory from the secure memory registry
		SecureMemoryRegistry::i()->remove(p);

#ifdef SENSITIVE_NON_PAGED
#ifndef _WIN32
		munlock((const void*) p, n * sizeof(T));
#else
		VirtualUnlock((const void*) p, n * sizeof(T));
#endif

#ifndef _WIN32
		free(p);
#else
		VirtualFree((const void*) r, MEM_RELEASE);
#endif
#else
		// Release the memory
		::operator delete((void*) p);
#endif // SENSITIVE_NON_PAGED
	}

	// Initialise allocate storage with a value
	void construct(pointer p, const T& value)
	{
		new((void*) p)T(value);
	}

	// Destroy elements of initialised storage
	void destroy(pointer p)
	{
		// Call destructor
		p->~T();
	}

	// Comparison operators
	inline bool operator==(SecureAllocator const&) const { return true; }
	inline bool operator!=(SecureAllocator const&) const { return false; }
};

#endif // !_SOFTHSM_V2_SECUREALLOCATOR_H

