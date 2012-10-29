#!/usr/bin/env bash
source `dirname "$0"`/lib.sh && init || exit 1

BOTAN="Botan-1.10.3"
BOTAN_URL="http://botan.randombit.net/files/$BOTAN.tgz"
BOTAN_FILENAME="$BOTAN.tgz"
BOTAN_HASH_TYPE="sha1"
BOTAN_HASH="0c0b2f6337d94245a32e215047311526652a114d"

check_if_built botan && exit 0
start_build botan

BOTAN_SRC=`fetch_src "$BOTAN_URL" "$BOTAN_FILENAME" "$BOTAN_HASH_TYPE" "$BOTAN_HASH"`

build_ok=0
case "$DISTRIBUTION" in
	centos | \
	redhat | \
	fedora | \
	sl | \
	ubuntu | \
	debian | \
	opensuse | \
	suse | \
	freebsd )
		(
			gunzip -c "$BOTAN_SRC" | tar xf - &&
			cd "$BOTAN" &&
			./configure.py --prefix="$INSTALL_ROOT" &&
			$MAKE &&
			$MAKE install
		) &&
		build_ok=1
		;;
	netbsd )
		(
			gunzip -c "$BOTAN_SRC" | tar xf - &&
			cd "$BOTAN" &&
			python2.7 ./configure.py --prefix="$INSTALL_ROOT" &&
			$MAKE &&
			$MAKE install
		) &&
		build_ok=1
		;;
	sunos )
		(
			gunzip -c "$BOTAN_SRC" | tar xf - &&
			cd "$BOTAN" &&
			./configure.py --prefix="$INSTALL_ROOT" \
				--disable-asm \
				--cpu=i686 &&
			$MAKE &&
			$MAKE install
		) &&
		build_ok=1
		;;
	openbsd )
		(
			gunzip -c "$BOTAN_SRC" | tar xf - &&
			cd "$BOTAN" &&
			python2.7 ./configure.py --prefix="$INSTALL_ROOT" \
				--disable-asm &&
			$MAKE &&
			$MAKE install
		) &&
		build_ok=1
		;;
esac

if [ "$build_ok" -eq 1 ]; then
	set_build_ok botan || exit 1
	exit 0
fi

exit 1
