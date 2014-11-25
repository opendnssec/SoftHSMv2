# FIPS 140-2

The OpenSSL crypto backend can be a FIPS 140-2 capable library,
cf. the OpenSSL FIPS 140 documents SecurityPolicy and UserGuide.

## Introduction

Please read the OpenSSL FIPS 140 documents about to get
a FIPS Capable OpenSSL library.

## Hard points

Reread the OpenSSL FIPS 140 documents as they are hard to apply.

Note the following is for Unix/Linux.

Now I suppose you have a >= 1.0.1e capable static library (a
dynamic library is far easier but always possible and often
dubious from a security point of view... BTW if you have built
a FIPS Capable OpenSSL library you should not be afraid of
extra complexity :-).

Do not forget to compile OpenSSL with position indepent code
(aka PIC) as the libsofthsm.so requires it. The FIPS module
canister is already compiled this way.

A usual issue is the C++ compiler not compiling .c files as C code.
A simple test can show this, put in foo.c file this code:

foo() { char *x = "ab"; }

and compile with the C and C++ compilers with all warnings:
the C++ compiler should raise an extra warning or error about
the no type for foo() and/or for the char* string constant.

When this raises some errors in the fispld script, you have to
insert '-x c' and '-x none' before and after each .c file
in the C++ commands, for instance using this wrapper:

-------------------------------- cut here --------------------------------
#!/bin/sh

commands="g++"

for elem in $@
do
 case $elem in
   *.c) commands+=" -x c $elem -x none";;
   *) commands+=" $elem";;
 esac
done

exec $commands
-------------------------------- end --------------------------------

In any cases you have to set CC and CXX to fipsld.
