/* config.h for WIN32 */

/* The default PKCS#11 library */
#define DEFAULT_PKCS11_LIB "softhsm2.dll"

/* The default location of softhsm2.conf */
#define DEFAULT_SOFTHSM2_CONF "softhsm2.conf"

/* The default location of the token directory */
#define DEFAULT_TOKENDIR "tokens"

/* Define to 1 if you have the `crypto' library (-lcrypto). */
#define HAVE_LIBCRYPTO 1

/* Whether LoadLibrary is available */
#define HAVE_LOADLIBRARY 1

/* Define to 1 if you have the <sqlite3.h> header file. */
#undef HAVE_SQLITE3_H

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#undef HAVE_UNISTD_H

/* Maximum PIN length */
#define MAX_PIN_LEN 255

/* Minimum PIN length */
#define MIN_PIN_LEN 4

/* Name of package */
#define PACKAGE "softhsm"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME "SoftHSM"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "SoftHSM 2.0.0a1"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "softhsm"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION  "2.0.0a1"

/* Non-paged memory for secure storage */
#undef SENSITIVE_NON_PAGE

/* The log level set by the user */
#define SOFTLOGLEVEL 3

/* Define to 1 if you have the ANSI C header files. */
#undef STDC_HEADERS

/* Version number of package */
#define VERSION  "2.0.0a1"

/* SoftHSM major version number via PKCS#11 */
#define VERSION_MAJOR 2

/* SoftHSM minor version number via PKCS#11 */
#define VERSION_MINOR 0

/* Compile with Botan support */
#define WITH_BOTAN 1

/* Compile with ECC support */
#define WITH_ECC 1

/* Compile with GOST support */
#define WITH_GOST 1

/* Compile with OpenSSL support */
#undef WITH_OPENSSL

/* Define to 1 if you have getpassphrase(). */
#define HAVE_GETPASSPHRASE

/* Addition things */

char *getpassphrase(const char *prompt);
int setenv(const char *name, const char *value, int overwrite);

/* At least Vista */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#define snprintf _snprintf
#define strcasecmp _stricmp
#define strncasecmp _strnicmp

/* Prevent inclusion of winsock.h in windows.h */

#define WIN32_LEAN_AND_MEAN 1

#include <windows.h>

/* avoid collision from min and max macros */

#undef min
#undef max

/* For Botan */

#pragma warning(disable: 4275 4267)

/* Temporary for debug */

#define DEBUG_LOG_STDERR 1

/* To avoid unsafe warnings (off) */

// #pragma warning(disable: 4996)
