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
 XMLConfigLoader.h

 Loads the configuration from the XML configuration file. This is currently a
 stub class that still needs to be implemented
 *****************************************************************************/

#ifndef _SOFTHSM_V2_XMLCONFIGLOADER_H
#define _SOFTHSM_V2_XMLCONFIGLOADER_H

#include "config.h"
#include "Configuration.h"

class XMLConfigLoader : public ConfigLoader
{
public:
	static XMLConfigLoader* i();

	virtual ~XMLConfigLoader() { }

	virtual bool loadConfiguration();

private:
	XMLConfigLoader();

	static XMLConfigLoader* instance;
};

#endif // !_SOFTHSM_V2_XMLCONFIGLOADER_H

