# Building SoftHSMv2 with CMake

## Configure

CMake can be configured using the following command:

	cmake -H. -Bbuild

Some options (more can be found in CMakeLists.txt):

	-DBUILD_TESTS=ON		Compile tests along with libraries
	-DDISABLE_NON_PAGED_MEMORY=ON	Disable non-paged memory for secure storage
	-DENABLE_EDDSA=ON		Enable support for EDDSA
	-DWITH_MIGRATE=ON		Build migration tool
	-DWITH_CRYPTO_BACKEND=openssl	Select crypto backend (openssl|botan)

## Compile

Compile the source code using the following command:

	make -C build

## Test

The tests can be run from the build directory:

	cd build
	ctest -V

## Install

Install the library using the follow command:

	cd ..
	sudo make -C build install
