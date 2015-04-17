# Building SoftHSMv2 on Mac OS X 10.8.5 (Mountain Lion)

This document contains instructions for building SoftHSMv2 from the command
line on Mac OS X 10.8.5.

This may work for other version of OS X, but that has not been verified.

## Command Line Tools

We assume that XCode has been installed. To find out where Xcode keeps the C++
compiler type the following at the command line:

	$ xcode-select --print-path
	/Applications/Xcode.app/Contents/Developer

The gcc compiler in this case can be found at
/Applications/Xcode.app/Contents/Developer/usr/bin/gcc

Alternatively if you don't want to install XCode you could install command line
tools for os x that can be downloaded from apple.

E.g. currently the following package for the mountain lion release of OS X is
available for download.

	command_line_tools_os_x_mountain_lion_for_xcode__october_2013.dmg

This dmg file is still 100MB but at least orders of magnitude smaller than
installing all of XCode.

## Homebrew

The libraries that come as part of OS X are rather old. We need to use more
recent versions of these libraries to avoid unexpected failures during building
and running.

There is a community supported command line package manager for installing the
dependencies we need. It's called homebrew. First we'll need to install it as
follows:

	$ ruby -e "$(curl -fsSL https://raw.github.com/mxcl/homebrew/go/install)"

Now we need to install some dependencies

	$ brew install automake
	$ brew install openssl
	$ brew install sqlite
	$ brew install cppunit

Because both openssl and sqlite are pre-installed on the system, the new
downloads are stored in an alternative location. /usr/local/opt

During configure the paths to the newly installed libraries needs to be passed
in so configure can actually find the libraries. We'll show how to do that
later.

## Cloning SoftHSMv2

We now need to clone SoftHSMv2 from github.

	$ git clone https://github.com/opendnssec/SoftHSMv2.git
	$ cd SoftHSMv2

I needed to change a line in configure.ac in order to prevent some errors
during configure.

Instead of the line:

	AM_INIT_AUTOMAKE(foreign)

I'm using

	AM_INIT_AUTOMAKE([foreign subdir-objects])

After changing this we can configure the build.

## Configuring the build

Start by installing autoconf in the source directory by executing the
autogen.sh script.

	$ sh ./autogen.sh

If all went well a configure script should have been generated. To find out the
options available for building issue the following command:

	$ ./configure --help

In the example below I will enable the optional token object store database
backend.

	$ ./configure --with-objectstore-backend-db \
		--with-openssl=/usr/local/opt/openssl \
		--with-sqlite3=/usr/local/opt/sqlite

Now if for some reason the compilers are not found, do the following at the
command line.

	$ export CC="xcrun gcc"
	$ export CPP="xcrun cpp"
	$ export CXX="xcrun g++"
	$ ./configure --with-objectstore-backend-db \
		--with-openssl=/usr/local/opt/openssl \
		--with-sqlite3=/usr/local/opt/sqlite

By exporting these environment variables we are instructing configure to use
the compilers stored inside the installed XCode.app.

## Building and Testing SoftHSMv2

Now we can build SoftHSMv2 by just executing make.

	$ make

And we can check that it works by running all tests.

	$ make check

To try a specific test, e.g. to check just the PKCS#11 test cases use the
following make command:

	$ make -C src/lib/test check

Then change src/lib/test/softhsm2.conf so it contains the following lines.

	# SoftHSM v2 configuration file
	directories.tokendir = ./tokens
	objectstore.backend = db

We are now ready to run the tests again.

	$ make -C src/lib/test check

Because the object store backend was changed from file to db we have used
sqlite for storing the token objects. Verify this by looking in the sub-folders
of src/lib/test/tokens There you should find a database file named sqlite3.db

## Performance

The file backend currently exhibits the best performance. It is normally at
least twice as fast as the database backend.

The idea behind storing token objects in a database is that it has advantages
when a large number (> 100K) of keys are stored in a token. A database allows
for selectively querying and loading in only a subset of the keys into memory.
The file based storage backend reads in the complete contents of the token.
Also because the database is only a single file, we should not hit any system
limitations w.r.t. the number of files that can be stored in a file system.

The database backend uses transactions to write changes to the token database.
For modifiable attributes this will require a round trip to the database every
time an attribute has been read as another process may have modified the given
attribute.

The database backend uses approximately 20% less memory because it will only
load in object attributes on demand. For non-mutable attributes that is not a
problem because once an object with its attributes is created those attributes
won't change. On the other hand the mutable attributes of the object are always
read when the object is accessed, making it slower because this will require a
roundtrip to the database for every mutable attribute. Note that most
attributes are non-mutable and especially the key material is non-mutable. So
once this (encrypted !) material has been read into memory it will remain
cached (encrypted !).

Currently the query functionality for only retrieving a subset of the objects
is not yet implemented. Therefore the database solution has no advantages
w.r.t. the file based solution for large number of files other than the 20%
less memory usage mentioned before.

For applications that need the highest speed possible and only read/use the
token, a solution would be to copy the whole of the token database to a
ramdisk. This should only be used when the application doesn't modify the
token, because a power-cycle of the host will wipe out the ramdisk.

