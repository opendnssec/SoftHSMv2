#!/usr/bin/env bash
source `dirname "$0"`/lib.sh && init || exit 1

BOTAN="Botan-2.5.0"
BOTAN_URL="https://botan.randombit.net/releases/$BOTAN.tgz"
BOTAN_FILENAME="$BOTAN.tgz"
BOTAN_HASH_TYPE="sha1"
BOTAN_HASH="f422ba87f99c070fdcc3347943cb1a63add2e028"

check_if_built botan && exit 0
start_build botan

BOTAN_SRC=`fetch_src "$BOTAN_URL" "$BOTAN_FILENAME" "$BOTAN_HASH_TYPE" "$BOTAN_HASH"`

build_ok=0
case "$DISTRIBUTION" in
	centos | \
	redhat | \
	fedora | \
	sl | \
	slackware | \
	ubuntu | \
	debian | \
	opensuse | \
	suse )
		(
			gunzip -c "$BOTAN_SRC" | tar xf - &&
			cd "$BOTAN" &&
			./configure.py --prefix="$INSTALL_ROOT" &&
			$MAKE &&
			$MAKE install
		) &&
		build_ok=1
		;;
	freebsd | \
	netbsd | \
	openbsd )
		opt=""
		if uname -a 2>/dev/null | grep -q "FreeBSD 10" 2>/dev/null; then
			opt="--cc=clang"
		fi
		(
			gunzip -c "$BOTAN_SRC" | tar xf - &&
			cd "$BOTAN" &&
			python2.7 ./configure.py --prefix="$INSTALL_ROOT" $opt &&
			$MAKE &&
			$MAKE install
		) &&
		build_ok=1
		;;
	sunos )
		platform=`uname -p`
		opt=""
		case "$platform" in
			i386)
				opt="--cpu=i686"
				;;

			sparc)
				opt="--cpu=sparc64"
				;;

			*)
				exit 1
				;;
		esac
		(
			gunzip -c "$BOTAN_SRC" | tar xf - &&
			cd "$BOTAN" &&
			./configure.py --prefix="$INSTALL_ROOT" $opt &&
			$MAKE &&
			$MAKE install
		) &&
		build_ok=1
		;;
esac

finish

if [ "$build_ok" -eq 1 ]; then
	set_build_ok botan || exit 1
	exit 0
fi

exit 1
