#!/bin/sh

case `uname` in Darwin*) glibtoolize --copy ;;
  *) libtoolize --copy ;; esac

aclocal -I m4 --install
autoheader
autoconf
automake --foreign --add-missing --force-missing --copy
