/* $Id$ */

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
 Configuration.cpp

 Loads the configuration and supports retrieval of configuration information
 *****************************************************************************/

#include <string>
#include <map>
#include "Configuration.h"
#include "log.h"

// Initialise the one-and-only instance
Configuration* Configuration::instance = NULL;

// Return the one-and-only instance
Configuration* Configuration::i()
{
	if (instance == NULL)
	{
		instance = new Configuration();
	}
	
	return NULL;
}

// Constructor
Configuration::Configuration()
{
	configLoader = NULL;
}

// Retrieve a string based configuration value
std::string Configuration::getString(std::string key, std::string ifEmpty /* = "" */)
{
	if (stringConfiguration.find(key) != stringConfiguration.end())
	{
		return stringConfiguration[key];
	}
	else
	{
		return ifEmpty;
	}
}

// Retrieve an integer configuration value
int Configuration::getInt(std::string key, int ifEmpty /* = 0 */)
{
	if (integerConfiguration.find(key) != integerConfiguration.end())
	{
		return integerConfiguration[key];
	}
	else
	{
		return ifEmpty;
	}
}

// Retrieve a boolean configuration value
bool Configuration::getBool(std::string key, bool ifEmpty /* = false */)
{
	if (booleanConfiguration.find(key) != booleanConfiguration.end())
	{
		return booleanConfiguration[key];
	}
	else
	{
		return ifEmpty;
	}
}

// Set a string based configuration value
void Configuration::setString(std::string key, std::string value)
{
	stringConfiguration[key] = value;
}

// Set an integer based configuration value
void Configuration::setInt(std::string key, int value)
{
	integerConfiguration[key] = value;
}

// Set a boolean configuration value
void Configuration::setBool(std::string key, bool value)
{
	booleanConfiguration[key] = value;
}

// Reload the configuration
void Configuration::reload()
{
	if (configLoader != NULL)
	{
		// Discard the current configuration
		stringConfiguration.clear();
		integerConfiguration.clear();
		booleanConfiguration.clear();

		// Reload the configuration
		if (!configLoader->loadConfiguration())
		{
			WARNING_MSG("Failed to load the SoftHSM configuration");
		}
	}
}

// Reload the configuration using the specified configuration loader
void Configuration::reload(ConfigLoader* configLoader)
{
	this->configLoader = configLoader;

	reload();
}

