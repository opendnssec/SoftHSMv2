/*
 * Copyright (c) 2010 .SE, The Internet Infrastructure Foundation
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
 SimpleConfigLoader.cpp

 Loads the configuration from the configuration file.
 *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <algorithm>
#include <limits.h>
#ifdef _WIN32
# include <io.h>
#else
# include <unistd.h>
#endif
#include "config.h"
#if defined(HAVE_GETPWUID_R)
# include <sys/types.h>
# include <pwd.h>
#endif
#include "SimpleConfigLoader.h"
#include "log.h"
#include "Configuration.h"

// Initialise the one-and-only instance
#ifdef HAVE_CXX11
std::unique_ptr<SimpleConfigLoader> SimpleConfigLoader::instance(nullptr);
#else
std::auto_ptr<SimpleConfigLoader> SimpleConfigLoader::instance(NULL);
#endif

// Return the one-and-only instance
SimpleConfigLoader* SimpleConfigLoader::i()
{
	if (instance.get() == NULL)
	{
		instance.reset(new SimpleConfigLoader());
	}

	return instance.get();
}

// Constructor
SimpleConfigLoader::SimpleConfigLoader()
{
}

// Load the configuration
bool SimpleConfigLoader::loadConfiguration()
{
	char* configPath = getConfigPath();

	FILE* fp = fopen(configPath,"r");

	if (fp == NULL)
	{
		ERROR_MSG("Could not open the config file: %s", configPath);
		free(configPath);
		return false;
	}
	free(configPath);

	char fileBuf[1024];

	// Format in config file
	//
	// <name> = <value>
	// # Line is ignored

	size_t line = 0;
	while (fgets(fileBuf, sizeof(fileBuf), fp) != NULL)
	{
		line++;

		// End the string at the first comment or newline
		fileBuf[strcspn(fileBuf, "#\n\r")] = '\0';

		// Skip empty lines
		if (fileBuf[0] == '\0')
		{
			continue;
		}

		// Get the first part of the line
		char* name = strtok(fileBuf, "=");
		if (name == NULL)
		{
			WARNING_MSG("Bad format on line %lu, skip", (unsigned long)line);
			continue;
		}

		// Trim the name
		char* trimmedName = trimString(name);
		if (trimmedName == NULL)
		{
			WARNING_MSG("Bad format on line %lu, skip", (unsigned long)line);
			continue;
		}

		// Get the second part of the line
		char* value = strtok(NULL, "=");
		if(value == NULL) {
			WARNING_MSG("Bad format on line %lu, skip", (unsigned long)line);
			free(trimmedName);
			continue;
		}

		// Trim the value
		char* trimmedValue = trimString(value);
		if (trimmedValue == NULL)
		{
			WARNING_MSG("Bad format on line %lu, skip", (unsigned long)line);
			free(trimmedName);
			continue;
		}

		// Save name,value
		std::string stringName(trimmedName);
		std::string stringValue(trimmedValue);
		free(trimmedName);
		free(trimmedValue);

		switch (Configuration::i()->getType(stringName))
		{
			case CONFIG_TYPE_STRING:
				Configuration::i()->setString(stringName, stringValue);
				break;
			case CONFIG_TYPE_INT:
				Configuration::i()->setInt(stringName, atoi(stringValue.c_str()));
				break;
			case CONFIG_TYPE_BOOL:
				bool boolValue;
				if (string2bool(stringValue, &boolValue))
				{
					Configuration::i()->setBool(stringName, boolValue);
				}
				else
				{
					WARNING_MSG("The value %s is not a boolean", stringValue.c_str());
				}
				break;
			case CONFIG_TYPE_UNSUPPORTED:
			default:
				WARNING_MSG("The following configuration is not supported: %s = %s",
					stringName.c_str(), stringValue.c_str());
				break;
		}
	}

	fclose(fp);

	return true;
}

// Get the boolean value from a string
bool SimpleConfigLoader::string2bool(std::string stringValue, bool* boolValue)
{
	// Convert to lowercase
	std::transform(stringValue.begin(), stringValue.end(), stringValue.begin(), tolower);

	if (stringValue.compare("true") == 0)
	{
		*boolValue = true;
		return true;
	}

	if (stringValue.compare("false") == 0)
	{
		*boolValue = false;
		return true;
	}

	return false;
}

#define CONFIG_FILE ".config/softhsm2/softhsm2.conf"

/* Returns a user-specific path for configuration.
 */
static char *get_user_path(void)
{
#ifdef _WIN32
	char path[512];
	const char *home_drive = getenv("HOMEDRIVE");
	const char *home_path = getenv("HOMEPATH");

	if (home_drive && home_path) {
		snprintf(path, sizeof(path), "%s%s\\softhsm2.conf", home_drive, home_path);

		if (_access(path, 0) == 0)
			return strdup(path);
	}
	goto fail;
#else
	char path[_POSIX_PATH_MAX];
	const char *home_dir = getenv("HOME");

	if (home_dir != NULL && home_dir[0] != 0) {
		snprintf(path, sizeof(path), "%s/" CONFIG_FILE, home_dir);
		if (access(path, R_OK) == 0)
			return strdup(path);
		else
			goto fail;
	}

# if defined(HAVE_GETPWUID_R)
	if (home_dir == NULL || home_dir[0] == '\0') {
		struct passwd *pwd;
		struct passwd _pwd;
		int ret;
		char tmp[512];

		ret = getpwuid_r(getuid(), &_pwd, tmp, sizeof(tmp), &pwd);
		if (ret == 0 && pwd != NULL) {
			snprintf(path, sizeof(path), "%s/" CONFIG_FILE, pwd->pw_dir);
			if (access(path, R_OK) == 0)
				return strdup(path);
			else
				goto fail;
		}
	}
# endif
#endif

 fail:
	return NULL;
}

static char *get_env_var_path(void)
{
#ifdef _WIN32

	LPSTR value = NULL;
	DWORD size = 0;

	size = GetEnvironmentVariableA("SOFTHSM2_CONF", value, size);
	if (size == 0) {
		return NULL;
	}

	value = (LPSTR) malloc(size);
	if (NULL == value) {
		return NULL;
	}

	if (GetEnvironmentVariableA("SOFTHSM2_CONF", value, size) != (size - 1)) {
		free(value);
		return NULL;
	}

	return value;

#else

	char *value = getenv("SOFTHSM2_CONF");

	if (value == NULL) {
		return value;
	} else {
		return strdup(value);
	}

#endif
}

char* SimpleConfigLoader::getConfigPath()
{
	char* configPath = get_env_var_path();
	char* tpath;

	if (configPath != NULL)
	{
		return configPath;
	}
	else
	{
		tpath = get_user_path();
		if (tpath != NULL)
		{
			return tpath;
		}
	}

	return strdup(DEFAULT_SOFTHSM2_CONF);
}

char* SimpleConfigLoader::trimString(char* text)
{
	if (text == NULL)
	{
		return NULL;
	}

	int startPos = 0;
	int endPos = strlen(text) - 1;

	// Find the first position without a space
	while (startPos <= endPos && isspace((int)*(text + startPos)))
	{
		startPos++;
	}
	// Find the last position without a space
	while (startPos <= endPos && isspace((int)*(text + endPos)))
	{
		endPos--;
	}

	// We must have a valid string
	int length = endPos - startPos + 1;
	if (length <= 0)
	{
		return NULL;
	}

	// Create the trimmed text
	char* trimmedText = (char*)malloc(length + 1);
	if (trimmedText == NULL)
	{
		return NULL;
	}
	trimmedText[length] = '\0';
	memcpy(trimmedText, text + startPos, length);

	return trimmedText;
}
