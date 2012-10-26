#!/usr/bin/env bash
source `dirname "$0"`/lib.sh && init || exit 1

check_if_built softhsm2 && exit 0
start_build softhsm2

build_ok=0
case "$DISTRIBUTION" in
	openbsd )
		export AUTOCONF_VERSION="2.68"
		export AUTOMAKE_VERSION="1.11"
		append_ldflags "-L/usr/local/lib"
		;;
esac
case "$DISTRIBUTION" in
	centos | \
	redhat | \
	fedora | \
	sl | \
	debian | \
	ubuntu | \
	opensuse )
		(
			sh autogen.sh &&
			mkdir -p build &&
			cd build &&
			../configure --prefix="$INSTALL_ROOT" \
				--with-migrate \
				--with-botan=/usr &&
			$MAKE &&
			$MAKE check &&
			$MAKE install &&
			cp "src/lib/common/softhsm2.conf" "$INSTALL_ROOT/etc/softhsm2.conf.build"
		) &&
		build_ok=1
		;;
	netbsd )
		(
			sh autogen.sh &&
			mkdir -p build &&
			cd build &&
			../configure --prefix="$INSTALL_ROOT" \
				--with-migrate \
				--with-botan=/usr/pkg \
				--with-sqlite3=/usr/pkg &&
			$MAKE &&
			$MAKE check &&
			$MAKE install &&
			cp "src/lib/common/softhsm2.conf" "$INSTALL_ROOT/etc/softhsm2.conf.build"
		) &&
		build_ok=1
		;;
	freebsd | \
	openbsd )
		(
			sh autogen.sh &&
			mkdir -p build &&
			cd build &&
			../configure --prefix="$INSTALL_ROOT" \
				--with-migrate \
				--with-botan=/usr/local \
				--with-sqlite3=/usr/local &&
			$MAKE &&
			$MAKE check &&
			$MAKE install &&
			cp "src/lib/common/softhsm2.conf" "$INSTALL_ROOT/etc/softhsm2.conf.build"
		) &&
		build_ok=1
		;;
	sunos | \
	suse )
		(
			sh autogen.sh &&
			mkdir -p build &&
			cd build &&
			../configure --prefix="$INSTALL_ROOT" \
				--with-migrate \
				--with-botan=/usr/local &&
			$MAKE &&
			$MAKE check &&
			$MAKE install &&
			cp "src/lib/common/softhsm2.conf" "$INSTALL_ROOT/etc/softhsm2.conf.build"
		) &&
		build_ok=1
		;;
esac

if [ "$build_ok" -eq 1 ]; then
	set_build_ok softhsm2 || exit 1
	exit 0
fi

exit 1
