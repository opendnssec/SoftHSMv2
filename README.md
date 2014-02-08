# SoftHSM version 2

SoftHSM is part of the OpenDNSSEC project. Read more at www.opendnssec.org.

## Introduction

OpenDNSSEC handles and stores its cryptographic keys via the PKCS#11 interface.
This interface specifies how to communicate with cryptographic devices such as
HSM:s (Hardware Security Modules) and smart cards. The purpose of these devices
is, among others, to generate cryptographic keys and sign information without
revealing private-key material to the outside world. They are often designed to
perform well on these specific tasks compared to ordinary processes in a normal
computer.

A potential problem with the use of the PKCS#11 interface is that it might
limit the wide spread use of OpenDNSSEC, since a potential user might not be
willing to invest in a new hardware device. To counter this effect, OpenDNSSEC
is providing a software implementation of a generic cryptographic device with a
PKCS#11 interface, the SoftHSM. SoftHSM is designed to meet the requirements of
OpenDNSSEC, but can also work together with other cryptographic products
because of the PKCS#11 interface.

## Developers

- Rickard Bellgrim (.SE, The Internet Infrastructure Foundation, www.iis.se)
- Francis Dupont (ISC, www.isc.org)
- René Post (XPT Software and Consulting, www.xpt.nl)
- Roland van Rijswijk (SURFnet bv, www.surfnet.nl)

## Dependencies

SoftHSM depends on a cryptographic library, Botan or OpenSSL.
Minimum required versions:

- Botan 1.10.0 
- OpenSSL 1.0.0

If you are using Botan, make sure that it has support for GNU MP (--with-gnump).
This will improve the performance when doing public key operations.

There is a migration tool for converting token databases from SoftHSMv1 into
the new type of tokens. If this tool is built, then SQLite3 is required (>=
3.4.2).

## Installation

### Configure

Configure the installation/compilation scripts:

	./configure

Options:

	--disable-non-paged-memory
				Disable non-paged memory for secure storage
				(default enabled)
	--disable-ecc		Disable support for ECC (default enabled)
	--disable-gost		Disable support for GOST (default enabled)
	--enable-visibility	Enable -fvisibility=hidden GCC flags so
				only the PKCS#11 C_* entry points are kept
	--with-crypto-backend	Select crypto backend (openssl|botan)
	--with-openssl=PATH	Specify prefix of path of OpenSSL
	--with-botan=PATH	Specify prefix of path of Botan
	--with-loglevel=INT	The log level. 0=No log 1=Error 2=Warning
				3=Info 4=Debug (default INT=3)
	--with-migrate		Build the migration tool. Used when migrating
				a SoftHSM v1 token database. Requires SQLite3
	--with-objectstore-backend-db
				Build with database object store (SQLite3)
	--with-sqlite3=PATH	Specify prefix of path of SQLite3

For more options:

	./configure --help


### Compile

Compile the source code using the following command:

	make

### Install Library

Install the library using the follow command:

	sudo make install

### Configure

The default location of the config file is /etc/softhsm2.conf. This location
can be change by setting the environment variable.

	export SOFTHSM2_CONF=/home/user/config.file

Details on the configuration can be found in "man softhsm2.conf".

### Initialize Tokens

Use either softhsm-util or the PKCS#11 interface. The SO PIN can e.g. be used
to re-initialize the token and the user PIN is handed out to the application so
it can interact with the token.

      softhsm-util --init-token --slot 0 --label "My token 1"

Type in SO PIN and user PIN. Once a token has been initialized, more slots will
be added automatically with a new uninitialized token.

### Link

Link to this library and use the PKCS#11 interface.


## Backup

All of the tokens and their objects are stored in the location given by
softhsm2.conf. Backup can thus be done as a regular file copy.


## Building from the repository

If the code is downloaded directly from the code repository, you have to
prepare the configuration scripts before continuing with the real README.

1. You need to install automake, autoconf, libtool, etc.
2. Run the command 'sh autogen.sh'
3. Continue reading this README.
