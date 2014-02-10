AC_DEFUN([ACX_VISIBILITY],[
	AC_ARG_ENABLE(
		[visibility],
		[AS_HELP_STRING([--enable-visibility],[enable hidden visibilty link mode @<:@disabled@:>@])],
		,
		[enable_visibility="no"]
	)
	if test "${enable_visibility}" = "yes"; then
		CFLAGS="${CFLAGS} -fvisibility=hidden"
		CXXFLAGS="${CXXFLAGS} -fvisibility=hidden"
		AC_DEFINE(CRYPTOKI_VISIBILITY, 1,
			  [Define to default visibility of PKCS@%:@11 entry points])
	fi
])
