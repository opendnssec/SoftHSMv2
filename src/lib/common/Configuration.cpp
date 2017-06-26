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
#ifdef HAVE_CXX11
std::unique_ptr<Configuration> Configuration::instance(nullptr);
#else
std::auto_ptr<Configuration> Configuration::instance(NULL);
#endif

// Add all valid configurations
const struct config Configuration::valid_config[] = {
	{ "directories.tokendir",	CONFIG_TYPE_STRING },
	{ "objectstore.backend",	CONFIG_TYPE_STRING },
	{ "log.level",			CONFIG_TYPE_STRING },
	{ "slots.removable",		CONFIG_TYPE_BOOL },
	{ "",				CONFIG_TYPE_UNSUPPORTED }
};

// Return the one-and-only instance
Configuration* Configuration::i()
{
	if (instance.get() == NULL)
	{
		instance.reset(new Configuration());
	}

	return instance.get();
}

// Constructor
Configuration::Configuration()
{
	configLoader = NULL;
}

// Get the type of the configuration value
int Configuration::getType(std::string key)
{
	for (int i = 0; valid_config[i].key.compare("") != 0; i++)
	{
		if (valid_config[i].key.compare(key) == 0)
		{
			return valid_config[i].type;
		}
	}

	return CONFIG_TYPE_UNSUPPORTED;
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
		WARNING_MSG("Missing %s in configuration. Using default value: %s", key.c_str(), ifEmpty.c_str());
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
		WARNING_MSG("Missing %s in configuration. Using default value: %i", key.c_str(), ifEmpty);
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
		WARNING_MSG("Missing %s in configuration. Using default value: %s", key.c_str(), ifEmpty ? "true" : "false");
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
bool Configuration::reload()
{
	if (configLoader == NULL)
	{
		return false;
	}

	// Discard the current configuration
	stringConfiguration.clear();
	integerConfiguration.clear();
	booleanConfiguration.clear();

	// Reload the configuration
	if (!configLoader->loadConfiguration())
	{
		ERROR_MSG("Failed to load the SoftHSM configuration");

		return false;
	}

	return true;
}

// Reload the configuration using the specified configuration loader
bool Configuration::reload(ConfigLoader* inConfigLoader)
{
	configLoader = inConfigLoader;

	return reload();
}

