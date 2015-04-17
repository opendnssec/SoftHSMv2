AC_DEFUN([ACX_VISIBILITY],[
	AC_ARG_ENABLE(
		[visibility],
		[AS_HELP_STRING([--disable-visibility],[disable hidden visibilty link mode @<:@enabled@:>@])],
		[enable_visibility="${enableval}"],
		[enable_visibility="yes"]
	)
	if test "${enable_visibility}" = "yes"; then
		CFLAGS="${CFLAGS} -fvisibility=hidden"
		CXXFLAGS="${CXXFLAGS} -fvisibility=hidden"
		AC_DEFINE(CRYPTOKI_VISIBILITY, 1,
			  [Define to default visibility of PKCS@%:@11 entry points])
	fi
])
