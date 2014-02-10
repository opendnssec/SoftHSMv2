#include <config.h>
#include <stdlib.h>
#include <string>

#ifdef _WIN32

int
setenv(const char *name, const char *value, int overwrite)
{
	std::string vv = name;
	vv += "=";
	vv += value;

	if (overwrite != 1)
		return false;

	return _putenv(vv.c_str()) == 0;
}

#endif
