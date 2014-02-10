AC_DEFUN([ACX_YIELD],[
	YIELD_LIB=
	# Solaris has sched_yield in librt, not in libpthread or libc.
	# Solaris 2.5.1, 2.6 has sched_yield in libposix4, not librt.
	AC_CHECK_LIB(rt, sched_yield, [YIELD_LIB=-lrt],
		[AC_CHECK_LIB(posix4, sched_yield, [YIELD_LIB=-lposix4])])
	AC_SUBST([YIELD_LIB])

	AC_CHECK_HEADER([sched.h])
])
