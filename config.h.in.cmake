/* config.h.in */

/* Define to default visibility of PKCS#11 entry points */
#cmakedefine01 CRYPTOKI_VISIBILITY

/* The default log level */
#cmakedefine DEFAULT_LOG_LEVEL "@DEFAULT_LOG_LEVEL@"

/* Default storage backend for token objects */
#cmakedefine DEFAULT_OBJECTSTORE_BACKEND "@DEFAULT_OBJECTSTORE_BACKEND@"

/* The default PKCS#11 library */
#cmakedefine DEFAULT_PKCS11_LIB "@DEFAULT_PKCS11_LIB@"

/* The default location of softhsm2.conf */
#cmakedefine DEFAULT_SOFTHSM2_CONF "@DEFAULT_SOFTHSM2_CONF@"

/* The default location of the token directory */
#cmakedefine DEFAULT_TOKENDIR "@DEFAULT_TOKENDIR@"

/* Define if advanced AES key wrap without pad is supported */
#cmakedefine01 HAVE_AES_KEY_WRAP

/* Define if advanced AES key wrap with pad is supported */
#cmakedefine01 HAVE_AES_KEY_WRAP_PAD

/* define if the compiler supports basic C++11 syntax */
#cmakedefine01 HAVE_CXX11

/* Define to 1 if you have the <dlfcn.h> header file. */
#cmakedefine01 HAVE_DLFCN_H

/* Define if you have dlopen */
#cmakedefine01 HAVE_DLOPEN

/* Define to 1 if you have the `getpwuid_r' function. */
#cmakedefine01 HAVE_GETPWUID_R

/* Define to 1 if you have the <inttypes.h> header file. */
#cmakedefine01 HAVE_INTTYPES_H

/* Define to 1 if you have the `crypto' library (-lcrypto). */
#cmakedefine01 HAVE_LIBCRYPTO

/* Define to 1 if you have the `sqlite3' library (-lsqlite3). */
#cmakedefine01 HAVE_LIBSQLITE3

/* Whether LoadLibrary is available */
#cmakedefine01 HAVE_LOADLIBRARY

/* Define to 1 if you have the <memory.h> header file. */
#cmakedefine01 HAVE_MEMORY_H

/* Build with object store database backend. */
#cmakedefine01 HAVE_OBJECTSTORE_BACKEND_DB

/* Define to 1 if you have the <openssl/ssl.h> header file. */
#cmakedefine01 HAVE_OPENSSL_SSL_H

/* Define to 1 if you have the <pthread.h> header file. */
#cmakedefine01 HAVE_PTHREAD_H

/* Define to 1 if you have the <sqlite3.h> header file. */
#cmakedefine01 HAVE_SQLITE3_H

/* Define to 1 if you have the <stdint.h> header file. */
#cmakedefine01 HAVE_STDINT_H

/* Define to 1 if you have the <stdlib.h> header file. */
#cmakedefine01 HAVE_STDLIB_H

/* Define to 1 if you have the <strings.h> header file. */
#cmakedefine01 HAVE_STRINGS_H

/* Define to 1 if you have the <string.h> header file. */
#cmakedefine01 HAVE_STRING_H

/* Define to 1 if you have the <sys/mman.h> header file. */
#cmakedefine01 HAVE_SYS_MMAN_H

/* Define to 1 if you have the <sys/stat.h> header file. */
#cmakedefine01 HAVE_SYS_STAT_H

/* Define to 1 if you have the <sys/types.h> header file. */
#cmakedefine01 HAVE_SYS_TYPES_H

/* Define to 1 if you have the <unistd.h> header file. */
#cmakedefine01 HAVE_UNISTD_H

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#cmakedefine LT_OBJDIR "@LT_OBJDIR@"

/* Maximum PIN length */
#cmakedefine MAX_PIN_LEN @MAX_PIN_LEN@

/* Minimum PIN length */
#cmakedefine MIN_PIN_LEN @MIN_PIN_LEN@

/* Name of package */
#cmakedefine PACKAGE "@PACKAGE@"

/* Define to the address where bug reports for this package should be sent. */
#cmakedefine PACKAGE_BUGREPORT "@PACKAGE_BUGREPORT@"

/* Define to the full name of this package. */
#cmakedefine PACKAGE_NAME "@PACKAGE_NAME@"

/* Define to the full name and version of this package. */
#cmakedefine PACKAGE_STRING "@PACKAGE_STRING@"

/* Define to the one symbol short name of this package. */
#cmakedefine PACKAGE_TARNAME "@PACKAGE_TARNAME@"

/* Define to the home page for this package. */
#cmakedefine PACKAGE_URL "@PACKAGE_URL@"

/* Define to the version of this package. */
#cmakedefine PACKAGE_VERSION "@PACKAGE_VERSION@"

/* Non-paged memory for secure storage */
#cmakedefine SENSITIVE_NON_PAGE

/* Define to 1 if you have the ANSI C header files. */
#cmakedefine STDC_HEADERS 1 // FIXME: CMake currently does not implement a way
                            //        to detect STDC_HEADERS like autotools

/* Version number of package */
#cmakedefine VERSION "@VERSION@"

/* SoftHSM major version number via PKCS#11 */
#cmakedefine VERSION_MAJOR @VERSION_MAJOR@

/* SoftHSM minor version number via PKCS#11 */
#cmakedefine VERSION_MINOR @VERSION_MINOR@

/* Compile with AES GCM */
#cmakedefine01 WITH_AES_GCM

/* Compile with Botan support */
#cmakedefine WITH_BOTAN

/* Compile with ECC support */
#cmakedefine01 WITH_ECC

/* Compile with FIPS 140-2 mode */
#cmakedefine01 WITH_FIPS

/* Compile with GOST support */
#cmakedefine01 WITH_GOST

/* Compile with OpenSSL support */
#cmakedefine01 WITH_OPENSSL

/* Compile with raw RSA PKCS PSS */
#cmakedefine01 WITH_RAW_PSS
