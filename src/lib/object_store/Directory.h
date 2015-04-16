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
 Directory.h

 Helper functions for accessing directories.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_DIRECTORY_H
#define _SOFTHSM_V2_DIRECTORY_H

#include "config.h"
#include "MutexFactory.h"
#include <string>
#include <vector>

class Directory
{
public:
	// Constructor
	Directory(std::string inPath);

	// Destructor
	virtual ~Directory();

	// Check if the directory is valid
	bool isValid();

	// Return a list of all files in a directory
	std::vector<std::string> getFiles();

	// Return a list of all subdirectories in a directory
	std::vector<std::string> getSubDirs();

	// Refresh the directory listing
	bool refresh();

	// Create a new subdirectory
	bool mkdir(std::string name);

	// Delete a subdirectory in the directory
	bool rmdir(std::string name, bool doRefresh = false);

	// Delete a file in the directory
	bool remove(std::string name);

private:
	// The directory path
	std::string path;

	// The status
	bool valid;

	// All files in the directory
	std::vector<std::string> files;

	// All subdirectories in the directory
	std::vector<std::string> subDirs;

	// For thread safeness
	Mutex* dirMutex;
};

#endif // !_SOFTHSM_V2_DIRECTORY_H

