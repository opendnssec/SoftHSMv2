# WIN32 Specific Notes

Works and checked on Visual Studio 2010 C++ Express, should work with any
Visual Studio 2010, 2012 or 2013 Desktop.

Default locations and names are:
OpenSSL in ssl directory at the same level, Botan in btn, CppUnit in cu,
if you want Debug versions you need ssl_d, btn_d and cu/lib/cppunitd.lib
or cu/cppunitd.lib. You can use the DLL or the static library for
Botan and OpenSSL, if it exists the DLL is copied in the Configuration
(i.e., Release or Debug) directory so is at the same place than
other binaries.

Configure scripts in win32, same syntax than autotools but without --,
e.g., 'perl Configure.pl with-crypto-backend=botan' (or if you prefer
Python 2 'python Configure.py with-crypto-backend=botan').

## Project List

- convarch: internal "convenience" static library
- softhsm2 (main project): softhsm2.dll
- keyconv, util, dump: softhsm2-keyconv.exe, softhsm2-util.exe, and
 softhsm2-dump-file.exe tools
- p11test, cryptotest, datamgrtest, handlemgrtest, objstoretest,
  sessionmgrtest, slotmgrtest: checking tools

## C4996 "unsafe" functions

- fopen
- getenv
- gmtime
- _snprintf (or snprintf on Visual Studio 14)
- sprintf
- sscanf
- strncpy
- strtok
- _vsnprintf
- vsnprintf
- vsprintf

## Port Summary (_WIN32 stuff)

- windows.h included from config.h with some tuning (so config.h should be
  included first)
- softhsm2.conf.win32 (installed by VS p11test project including in the topdir)
- No unistd.h, sys/mman.h, sys/socket.h, etc
- sys/time.h -> time.h
- / in file path -> \ (\\\\ in chars/strings)
- \_\_func\_\_ -> \_\_FUNCTION\_\_ (should be _MSC_VER in place of _WIN32?)
- wb/rb in fopen for binary files
- dlopen & co -> LoadLibrary & co
- valloc, mlock, etc -> VirtualAlloc, VirtualLock, etc
- threadID -> GetCurrentThreadId
- pthread_mutex -> Mutex (note CreateMutex is now defined by config.h)
- dirent & co -> _findfirst & co
- remove -> _rmdir or _unlink (WIN32 remove() doesn't handle directories)
- fcntl F_SETL & co* -> LockFileEx & co
- shell "rm -rf foo" -> cmd.exe "rmdir /s /q foo 2> nul"
- syslog -> provided using Event
- getopt, getpassphrase -> provided
- setenv -> provided using _putenv
