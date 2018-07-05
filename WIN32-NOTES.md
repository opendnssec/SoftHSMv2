# Building SoftHSM2 for Windows

This document describes process of building both 32-bit and 64-bit versions of SoftHSM2 on 64-bit Windows 8.1 machine.
Either OpenSSL or Botan can be used as the crypto backend.

## Required software

- [Visual Studio](https://www.visualstudio.com/products/visual-studio-community-vs) (2015 Community)
- [GNU Privacy Guard for Windows](http://www.gpg4win.org/) (2.2.5)
- [7-zip](http://www.7-zip.org/) (9.20)
- [Strawberry Perl](http://strawberryperl.com/) (5.22.0.1)
- [The Netwide Assembler](http://www.nasm.us/) (2.11.08)
- [Python](https://www.python.org/downloads/windows/) (3.4.2)

## Prepare working directories

    mkdir C:\build\bin\
    mkdir C:\build\src\

## Build OpenSSL 1.0.2d static library

Download [OpenSSL 1.0.2d](http://openssl.org/source/openssl-1.0.2d.tar.gz) with [its signature](http://openssl.org/source/openssl-1.0.2d.tar.gz.asc) into `C:\build\src\` directory and verify signature of the downloaded archive:

    cd C:\build\src\
    gpg --keyserver pgp.mit.edu --recv-keys 0E604491
    gpg --verify openssl-1.0.2d.tar.gz.asc openssl-1.0.2d.tar.gz

### 32-bit

Extract archive `openssl-1.0.2d.tar.gz` into `C:\build\src\openssl-1.0.2d-x86` directory:

    cd C:\build\src\
    "C:\Program Files\7-Zip\7z" x openssl-1.0.2d.tar.gz
    "C:\Program Files\7-Zip\7z" x openssl-1.0.2d.tar
    rename openssl-1.0.2d openssl-1.0.2d-x86
    del openssl-1.0.2d.tar*

In a **new command line window** build OpenSSL and install it into `C:\build\bin\openssl-1.0.2d-x86` directory:

    cd C:\build\src\openssl-1.0.2d-x86
    set PATH=%PATH%;C:\nasm
    "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat"
    perl Configure VC-WIN32 --prefix=C:\build\bin\openssl-1.0.2d-x86 enable-static-engine
    ms\do_nasm
    nmake /f ms\nt.mak
    nmake /f ms\nt.mak test
    nmake /f ms\nt.mak install

## 64-bit

Extract archive `openssl-1.0.2d.tar.gz` into `C:\build\src\openssl-1.0.2d-x64` directory:

    cd C:\build\src\
    "C:\Program Files\7-Zip\7z" x openssl-1.0.2d.tar.gz
    "C:\Program Files\7-Zip\7z" x openssl-1.0.2d.tar
    rename openssl-1.0.2d openssl-1.0.2d-x64
    del openssl-1.0.2d.tar*

In a **new command line window** build OpenSSL and install it into `C:\build\bin\openssl-1.0.2d-x64` directory:

    cd C:\build\src\openssl-1.0.2d-x64
    set PATH=%PATH%;C:\nasm
    "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" amd64
    perl Configure VC-WIN64A --prefix=C:\build\bin\openssl-1.0.2d-x64 enable-static-engine
    ms\do_win64a
    nmake /f ms\nt.mak
    nmake /f ms\nt.mak test
    nmake /f ms\nt.mak install

## Build OpenSSL 1.1.0a static library

Download [OpenSSL 1.1.0a](https://www.openssl.org/source/openssl-1.1.0a.tar.gz) with [its signature](https://www.openssl.org/source/openssl-1.1.0a.tar.gz.asc) into `C:\build\src\` directory and verify signature of the downloaded archive:

    cd C:\build\src\
    gpg --keyserver pgp.mit.edu --recv-keys 0E604491
    gpg --verify openssl-1.1.0a.tar.gz.asc openssl-1.1.0a.tar.gz

### 32-bit

Extract archive `openssl-1.1.0a.tar.gz` into `C:\build\src\openssl-1.1.0a-x86` directory:

    cd C:\build\src\
    "C:\Program Files\7-Zip\7z" x openssl-1.1.0a.tar.gz
    "C:\Program Files\7-Zip\7z" x openssl-1.1.0a.tar
    rename openssl-1.1.0a openssl-1.1.0a-x86
    del openssl-1.1.0a.tar*

In a **new command line window** build OpenSSL and install it into `C:\build\bin\openssl-1.1.0a-x86` directory:

    cd C:\build\src\openssl-1.1.0a-x86
    set PATH=%PATH%;C:\nasm
    "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat"
    perl Configure VC-WIN32 --prefix=C:\build\bin\openssl-1.1.0a-x86 --openssldir=C:\build\bin\openssl-1.1.0a-x86\ssl no-shared
    nmake
    nmake test
    nmake install

## 64-bit

Extract archive `openssl-1.1.0a.tar.gz` into `C:\build\src\openssl-1.1.0a-x64` directory:

    cd C:\build\src\
    "C:\Program Files\7-Zip\7z" x openssl-1.1.0a.tar.gz
    "C:\Program Files\7-Zip\7z" x openssl-1.1.0a.tar
    rename openssl-1.1.0a openssl-1.1.0a-x64
    del openssl-1.1.0a.tar*

In a **new command line window** build OpenSSL and install it into `C:\build\bin\openssl-1.1.0a-x64` directory:

    cd C:\build\src\openssl-1.1.0a-x64
    set PATH=%PATH%;C:\nasm
    "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" amd64
    perl Configure VC-WIN64A --prefix=C:\build\bin\openssl-1.1.0a-x64 --openssldir=C:\build\bin\openssl-1.1.0a-x64\ssl no-shared
    nmake
    nmake test
    nmake install
	
## Build Botan 1.10.10

Download [Botan 1.10.10](http://botan.randombit.net/releases/Botan-1.10.10.tgz) with [its signature](http://botan.randombit.net/releases/Botan-1.10.10.tgz.asc) into `C:\build\src\` directory and verify signature of the downloaded archive:

    cd C:\build\src\
    gpg --keyserver pgp.mit.edu --recv-keys EFBADFBC
    gpg --verify Botan-1.10.10.tgz.asc Botan-1.10.10.tgz

### 32-bit

Extract archive `Botan-1.10.10.tgz` into `C:\build\src\botan-1.10.10-x86` directory:

    cd C:\build\src\
    rename Botan-1.10.10.tgz Botan-1.10.10.tar.gz
    "C:\Program Files\7-Zip\7z" x Botan-1.10.10.tar.gz
    "C:\Program Files\7-Zip\7z" x Botan-1.10.10.tgz
    rename Botan-1.10.10 botan-1.10.10-x86
    del Botan-1.10.10.t*

In a **new command line window as admin** build Botan and install it into `C:\build\bin\botan-1.10.10-x86` directory. Need to run the configure script as admin so it can link objects:

    cd C:\build\src\botan-1.10.10-x86
    "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat"
    python configure.py --cc=msvc --cpu=x86 --prefix=C:\build\bin\botan-1.10.10-x86
    nmake
    nmake check
    check.exe --validate
    nmake install

## 64-bit

Extract archive `Botan-1.10.10.tgz` into `C:\build\src\botan-1.10.10-x64` directory:

    cd C:\build\src\
    rename Botan-1.10.10.tgz Botan-1.10.10.tar.gz
    "C:\Program Files\7-Zip\7z" x Botan-1.10.10.tar.gz
    "C:\Program Files\7-Zip\7z" x Botan-1.10.10.tgz
    rename Botan-1.10.10 botan-1.10.10-x64
    del Botan-1.10.10.t*

In a **new command line window as admin** build Botan and install it into `C:\build\bin\botan-1.10.10-x64` directory. Need to run the configure script as admin so it can link objects:

    cd C:\build\src\botan-1.10.10-x64
    "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" amd64
    python configure.py --cc=msvc --cpu=x64 --prefix=C:\build\bin\botan-1.10.10-x64
    nmake
    nmake check
    check.exe --validate
    nmake install

## Build CppUnit 1.13.2 unicode library

Download [CppUnit 1.13.2](http://dev-www.libreoffice.org/src/cppunit-1.13.2.tar.gz) into `C:\build\src\` directory.

### 32-bit

Extract archive `cppunit-1.13.2.tar.gz` into `C:\build\src\cppunit-1.13.2-x86` directory:

    cd C:\build\src\
    "C:\Program Files\7-Zip\7z" x cppunit-1.13.2.tar.gz
    "C:\Program Files\7-Zip\7z" x cppunit-1.13.2.tar
    rename cppunit-1.13.2 cppunit-1.13.2-x86
    del cppunit-1.13.2.tar*

Open solution `C:\build\src\cppunit-1.13.2-x86\src\CppUnitLibraries2010.sln` in Visual Studio and rebuild the source with `Release Unicode\Win32` solution configuration.

(If you want to compile SoftHSM with static CRT, then you must also compile CppUnit with static CRT. Change "Runtime Library" to "Multi-threaded (/MT)" in the project "cppunit". This will create some build errors for project "TestRunner", but that can be ignored since it is not used by SoftHSM.)

Copy the results into `C:\build\bin\cppunit-1.13.2-x86` directory:

    mkdir C:\build\bin\cppunit-1.13.2-x86\lib
    xcopy C:\build\src\cppunit-1.13.2-x86\lib C:\build\bin\cppunit-1.13.2-x86\lib /E
    mkdir C:\build\bin\cppunit-1.13.2-x86\include
    xcopy C:\build\src\cppunit-1.13.2-x86\include C:\build\bin\cppunit-1.13.2-x86\include /E

### 64-bit

Extract archive `cppunit-1.13.2.tar.gz` into `C:\build\src\cppunit-1.13.2-x64` directory:

    cd C:\build\src\
    "C:\Program Files\7-Zip\7z" x cppunit-1.13.2.tar.gz
    "C:\Program Files\7-Zip\7z" x cppunit-1.13.2.tar
    rename cppunit-1.13.2 cppunit-1.13.2-x64
    del cppunit-1.13.2.tar*

Open solution `C:\build\src\cppunit-1.13.2-x64\src\CppUnitLibraries2010.sln` in Visual Studio and rebuild the source with `Release Unicode\x64` solution configuration.

(If you want to compile SoftHSM with static CRT, then you must also compile CppUnit with static CRT. Change "Runtime Library" to "Multi-threaded (/MT)" in the project "cppunit". This will create some build errors for project "TestRunner", but that can be ignored since it is not used by SoftHSM.)

Copy the results into `C:\build\bin\cppunit-1.13.2-x64` directory:

    mkdir C:\build\bin\cppunit-1.13.2-x64\lib
    xcopy C:\build\src\cppunit-1.13.2-x64\lib C:\build\bin\cppunit-1.13.2-x64\lib /E
    mkdir C:\build\bin\cppunit-1.13.2-x64\include
    xcopy C:\build\src\cppunit-1.13.2-x64\include C:\build\bin\cppunit-1.13.2-x64\include /E

## Build SoftHSM

Download the latest version of [SoftHSMv2](https://dist.opendnssec.org/source/) with its signature into `C:\build\src\` directory and verify signature of the downloaded archive:

    cd C:\build\src\
    gpg --keyserver pgp.surfnet.nl --recv-keys 4FCB0B94
    gpg --verify softhsm-2.x.y.tar.gz.sig softhsm-2.x.y.tar.gz
    "C:\Program Files\7-Zip\7z" x softhsm-2.x.y.tar.gz
    "C:\Program Files\7-Zip\7z" x softhsm-2.x.y.tar
    rename softhsm-2.x.y SoftHSMv2
    del softhsm-2.x.y.tar*

Or clone the source code from GitHub:

    cd C:\build\src\
    git clone https://github.com/opendnssec/SoftHSMv2.git
	
### 32-bit

Configure build process in a **new command line window**:

    cd C:\build\src\SoftHSMv2\win32\
    "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat"

OpenSSL (OpenSSL GOST engine does not support OpenSSL 1.1.0) or Botan crypto backend:

    python Configure.py disable-debug disable-gost with-crypto-backend=openssl with-openssl=C:\build\bin\openssl-1.1.0a-x86\ with-cppunit=C:\build\bin\cppunit-1.13.2-x86\
    python Configure.py disable-debug with-crypto-backend=botan with-botan=C:\build\bin\botan-1.10.10-x86\ with-cppunit=C:\build\bin\cppunit-1.13.2-x86\

(Add option enable-static-runtime if you want to compile with static CRT (/MT))

Open solution `C:\build\src\SoftHSMv2\win32\softhsm2.sln` in Visual Studio and rebuild the source with `Release\Win32` solution configuration.

Verify the build by running the test programs:

    C:\build\src\SoftHSMv2\win32\Release\cryptotest.exe
    C:\build\src\SoftHSMv2\win32\Release\datamgrtest.exe
    C:\build\src\SoftHSMv2\win32\Release\handlemgrtest.exe
    C:\build\src\SoftHSMv2\win32\Release\objstoretest.exe
    C:\build\src\SoftHSMv2\win32\Release\p11test.exe
    C:\build\src\SoftHSMv2\win32\Release\sessionmgrtest.exe
    C:\build\src\SoftHSMv2\win32\Release\slotmgrtest.exe

Copy the results into `C:\build\bin\SoftHSMv2-x86` directory:

    mkdir C:\build\bin\SoftHSMv2-x86
    mkdir C:\build\bin\SoftHSMv2-x86\tokens
    copy C:\build\src\SoftHSMv2\win32\Release\softhsm2.dll C:\build\bin\SoftHSMv2-x86\
    copy C:\build\src\SoftHSMv2\win32\Release\softhsm2-dump-file.exe C:\build\bin\SoftHSMv2-x86\
    copy C:\build\src\SoftHSMv2\win32\Release\softhsm2-keyconv.exe C:\build\bin\SoftHSMv2-x86\
    copy C:\build\src\SoftHSMv2\win32\Release\softhsm2-util.exe C:\build\bin\SoftHSMv2-x86\
    copy C:\build\src\SoftHSMv2\src\lib\common\softhsm2.conf.in C:\build\bin\SoftHSMv2-x86\softhsm2.conf

Replace `@softhsmtokendir@` with `C:\build\bin\SoftHSMv2-x86\tokens` in the file `C:\build\bin\SoftHSMv2-x86\softhsm2.conf`

Set the environment variable SOFTHSM2_CONF to `C:\build\bin\SoftHSMv2-x86\softhsm2.conf`

### 64-bit

Configure build process in a **new command line window**:

    cd C:\build\src\SoftHSMv2\win32\
    "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" amd64

OpenSSL (OpenSSL GOST engine does not support OpenSSL 1.1.0) or Botan crypto backend:

    python Configure.py enable-64bit disable-debug disable-gost with-crypto-backend=openssl with-openssl=C:\build\bin\openssl-1.1.0a-x64\ with-cppunit=C:\build\bin\cppunit-1.13.2-x64\
    python Configure.py enable-64bit disable-debug with-crypto-backend=botan with-botan=C:\build\bin\botan-1.10.10-x64\ with-cppunit=C:\build\bin\cppunit-1.13.2-x64\

(Add option enable-static-runtime if you want to compile with static CRT (/MT))

Open solution `C:\build\src\SoftHSMv2\win32\softhsm2.sln` in Visual Studio and rebuild the source with `Release\x64` solution configuration.

Verify the build by running the test programs:

    C:\build\src\SoftHSMv2\win32\x64\Release\cryptotest.exe
    C:\build\src\SoftHSMv2\win32\x64\Release\datamgrtest.exe
    C:\build\src\SoftHSMv2\win32\x64\Release\handlemgrtest.exe
    C:\build\src\SoftHSMv2\win32\x64\Release\objstoretest.exe
    C:\build\src\SoftHSMv2\win32\x64\Release\p11test.exe
    C:\build\src\SoftHSMv2\win32\x64\Release\sessionmgrtest.exe
    C:\build\src\SoftHSMv2\win32\x64\Release\slotmgrtest.exe

Copy the results into `C:\build\bin\SoftHSMv2-x64` directory:

    mkdir C:\build\bin\SoftHSMv2-x64
    mkdir C:\build\bin\SoftHSMv2-x64\tokens
    copy C:\build\src\SoftHSMv2\win32\x64\Release\softhsm2.dll C:\build\bin\SoftHSMv2-x64\
    copy C:\build\src\SoftHSMv2\win32\x64\Release\softhsm2-dump-file.exe C:\build\bin\SoftHSMv2-x64\
    copy C:\build\src\SoftHSMv2\win32\x64\Release\softhsm2-keyconv.exe C:\build\bin\SoftHSMv2-x64\
    copy C:\build\src\SoftHSMv2\win32\x64\Release\softhsm2-util.exe C:\build\bin\SoftHSMv2-x64\
    copy C:\build\src\SoftHSMv2\src\lib\common\softhsm2.conf.in C:\build\bin\SoftHSMv2-x64\softhsm2.conf

Replace `@softhsmtokendir@` with `C:\build\bin\SoftHSMv2-x64\tokens` in the file `C:\build\bin\SoftHSMv2-x64\softhsm2.conf`

Set the environment variable SOFTHSM2_CONF to `C:\build\bin\SoftHSMv2-x64\softhsm2.conf`

## Continue reading in the README
