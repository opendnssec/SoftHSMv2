# Building SoftHSMv2 for Windows

This document describes process of building both 32-bit and 64-bit versions of SoftHSMv2.

## Required software

- [Visual Studio](https://visualstudio.microsoft.com/vs/community/) (Community)
- [C/C++ dependency manager from Microsoft](https://vcpkg.io/)
- [CMake](https://cmake.org/)

## Prepare working directories

	set VCPKG_HOME=C:\Projects\vcpkg
	set SOFTHSM_HOME=C:\Projects\SoftHSMv2
	git clone https://github.com/opendnssec/SoftHSMv2.git %SOFTHSM_HOME%
	git clone https://github.com/Microsoft/vcpkg.git %VCPKG_HOME%

## Build dependencies

	cd %VCPKG_HOME%
	bootstrap-vcpkg.bat
	git fetch
	git checkout 2021.05.12

	vcpkg install cppunit:x86-windows
	vcpkg install cppunit:x86-windows-static
	vcpkg install openssl-windows:x86-windows
	vcpkg install botan:x86-windows
	vcpkg install sqlite3:x86-windows

	vcpkg install cppunit:x64-windows
	vcpkg install cppunit:x64-windows-static
	vcpkg install openssl-windows:x64-windows
	vcpkg install botan:x64-windows
	vcpkg install sqlite3:x64-windows

	vcpkg integrate install

## Configure SoftHSMv2

Build can be configured using the following commands:

	mkdir %SOFTHSM_HOME%\tmp32
	cd %SOFTHSM_HOME%\tmp32
	cmake .. -G "Visual Studio 15 2017" -A Win32 -DCMAKE_TOOLCHAIN_FILE=%VCPKG_HOME%\scripts\buildsystems\vcpkg.cmake -DCMAKE_INSTALL_PREFIX=%SOFTHSM_HOME%\out32 -DBUILD_TESTS=ON -DWITH_CRYPTO_BACKEND=openssl -DWITH_OBJECTSTORE_BACKEND_DB=OFF

	mkdir %SOFTHSM_HOME%\tmp64
	cd %SOFTHSM_HOME%\tmp64
	cmake .. -G "Visual Studio 15 2017" -A x64 -DCMAKE_TOOLCHAIN_FILE=%VCPKG_HOME%\scripts\buildsystems\vcpkg.cmake -DCMAKE_INSTALL_PREFIX=%SOFTHSM_HOME%\out64 -DBUILD_TESTS=ON -DWITH_CRYPTO_BACKEND=botan -DWITH_OBJECTSTORE_BACKEND_DB=ON

Some options (more can be found in CMakeLists.txt):

	-DBUILD_TESTS=ON                Compile tests along with libraries
	-DENABLE_EDDSA=ON               Enable support for EDDSA
	-DWITH_MIGRATE=ON               Build migration tool
	-DWITH_CRYPTO_BACKEND=          Select crypto backend (openssl|botan)
	-DDISABLE_NON_PAGED_MEMORY=ON   Disable non-paged memory for secure storage
	-DWITH_OBJECTSTORE_BACKEND_DB=ON	Enable sqlite3 data storage

## Compile

Compile the source code using the following command:

	cmake --build . --config RelWithDebInfo

## Test

	ctest -C RelWithDebInfo --output-on-failure --progress --verbose

## Install

Install the library using the follow command:

	cmake  -DCMAKE_INSTALL_CONFIG_NAME=RelWithDebInfo  -P cmake_install.cmake
