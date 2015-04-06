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
 Configuration.h

 Loads the configuration and supports retrieval of configuration information
 *****************************************************************************/

#ifndef _SOFTHSM_V2_CONFIGURATION_H
#define _SOFTHSM_V2_CONFIGURATION_H

#include "config.h"
#include <string>
#include <map>
#include <memory>

enum
{
	CONFIG_TYPE_UNSUPPORTED,
	CONFIG_TYPE_STRING,
	CONFIG_TYPE_INT,
	CONFIG_TYPE_BOOL
};

struct config
{
	std::string key;
	int type;
};

class ConfigLoader
{
public:
	virtual ~ConfigLoader() { }

	// Trigger loading of the configuration
	virtual bool loadConfiguration() = 0;
};

class Configuration
{
public:
	static Configuration* i();

	virtual ~Configuration() { }

	// Get the type of the configuration value
	int getType(std::string key);

	// Retrieve a string based configuration value
	std::string getString(std::string key, std::string ifEmpty = std::string(""));

	// Retrieve an integer configuration value
	int getInt(std::string key, int ifEmpty = 0);

	// Retrieve a boolean configuration value
	bool getBool(std::string key, bool ifEmpty = false);

	// Set a string based configuration value
	void setString(std::string key, std::string value);

	// Set an integer based configuration value
	void setInt(std::string key, int value);

	// Set a boolean configuration value
	void setBool(std::string key, bool value);

	// Reload the configuration
	bool reload();

	// Reload the configuration using the specified configuration loader
	bool reload(ConfigLoader* inConfigLoader);

private:
	Configuration();

#ifdef HAVE_CXX11
	static std::unique_ptr<Configuration> instance;
#else
	static std::auto_ptr<Configuration> instance;
#endif

	std::map<std::string, std::string> stringConfiguration;
	std::map<std::string, int> integerConfiguration;
	std::map<std::string, bool> booleanConfiguration;

	ConfigLoader* configLoader;

	static const struct config valid_config[];
};

#endif // !_SOFTHSM_V2_CONFIGURATION_H

