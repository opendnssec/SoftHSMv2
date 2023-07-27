#!/bin/sh

CONF_CPP_LIBRARY_ASSERTIONS=""
CONF_CRYPTO=""
CONF_OBJSTORE=""

case $CPP_LIBRARY_ASSERTIONS in
yes)
	CONF_CPP_LIBRARY_ASSERTIONS="$CONF_CPP_LIBRARY_ASSERTIONS -D_LIBCPP_DEBUG_LEVEL=1 -D_GLIBCXX_ASSERTIONS=1"
esac

case $CRYPTO in
botan)
	CONF_CRYPTO="$CONF_CRYPTO --with-crypto-backend=botan --with-botan=/usr"
	CONF_CRYPTO="$CONF_CRYPTO --disable-ecc --disable-eddsa --disable-gost"
	;;
openssl)
	CONF_CRYPTO="$CONF_CRYPTO --with-crypto-backend=openssl --with-openssl=/usr"
	CONF_CRYPTO="$CONF_CRYPTO --disable-eddsa --disable-gost"
	openssl version -a
	;;
*)
	echo "Unknown crypto backend"
	exit 1
esac

case $OBJSTORE in
file)
	CONF_OBJSTORE="$CONF_OBJSTORE"
	;;
sqlite)
	CONF_OBJSTORE="$CONF_OBJSTORE --with-objectstore-backend-db --with-migrate"
	;;
*)
	echo "Unknown objectstore backend"
	exit 1
esac

sh autogen.sh && \
env CXXFLAGS="${CXXFLAGS} ${CONF_CPP_LIBRARY_ASSERTIONS}" ./configure $CONF_CRYPTO $CONF_OBJSTORE && \
make all check
