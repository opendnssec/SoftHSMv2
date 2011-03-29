/* $Id$ */

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
#include "config.h"
#include "SimpleConfigLoader.h"
#include "log.h"
#include "Configuration.h"

// Initialise the one-and-only instance
std::auto_ptr<SimpleConfigLoader> SimpleConfigLoader::instance(NULL);

// Return the one-and-only instance
SimpleConfigLoader* SimpleConfigLoader::i()
{
	if (instance.get() == NULL)
	{
		instance = std::auto_ptr<SimpleConfigLoader>(new SimpleConfigLoader());
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
	const char* configPath = getConfigPath();

	FILE* fp = fopen(configPath,"r");

	if (fp == NULL)
	{
		ERROR_MSG("Could not open the config file: %s", configPath);
		return false;
	}

	char fileBuf[1024];

	// Format in config file
	//
	// <name> = <value>
	// # Line is ignored

	while (fgets(fileBuf, sizeof(fileBuf), fp) != NULL)
	{
		// End the string at the first comment or newline
		fileBuf[strcspn(fileBuf, "#\n\r")] = '\0';

		// Get the first part of the line
		char* name = strtok(fileBuf, "=");
		if (name == NULL)
		{
			continue;
		}

		// Trim the name
		char* trimmedName = trimString(name);
		if (trimmedName == NULL)
		{
			continue;
		}

		// Get the second part of the line
		char* value = strtok(NULL, "=");
		if(value == NULL) {
			free(trimmedName);
			continue;
		}

		// Trim the value
		char* trimmedValue = trimString(value);
		if (trimmedValue == NULL)
		{
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

const char* SimpleConfigLoader::getConfigPath()
{
	const char* configPath = getenv("SOFTHSM2_CONF");

	if (configPath == NULL) {
		configPath = DEFAULT_SOFTHSM2_CONF;
	}

	return configPath;
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
