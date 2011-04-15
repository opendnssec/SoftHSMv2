# $Id$

AC_DEFUN([ACX_SEMAPHORE],[
	SEMAPHORE_LIB=

	AC_CHECK_LIB(
		rt,
		sem_open,
		[
			AC_CHECK_LIB(rt, sem_close,    [], AC_MSG_ERROR([Could not find sem_close]))
			AC_CHECK_LIB(rt, sem_unlink,   [], AC_MSG_ERROR([Could not find sem_unlink]))
			AC_CHECK_LIB(rt, sem_post,     [], AC_MSG_ERROR([Could not find sem_post]))
			AC_CHECK_LIB(rt, sem_wait,     [], AC_MSG_ERROR([Could not find sem_wait]))
			AC_CHECK_LIB(rt, sem_trywait,  [], AC_MSG_ERROR([Could not find sem_trywait]))
			AC_CHECK_LIB(rt, sem_getvalue, [], AC_MSG_ERROR([Could not find sem_getvalue]))
			SEMAPHORE_LIB=-lrt
		],
		[
			AC_CHECK_LIB(
				posix4,
				sem_open,
				[
					AC_CHECK_LIB(posix4, sem_close,    [], AC_MSG_ERROR([Could not find sem_close]))
					AC_CHECK_LIB(posix4, sem_unlink,   [], AC_MSG_ERROR([Could not find sem_unlink]))
					AC_CHECK_LIB(posix4, sem_post,     [], AC_MSG_ERROR([Could not find sem_post]))
					AC_CHECK_LIB(posix4, sem_wait,     [], AC_MSG_ERROR([Could not find sem_wait]))
					AC_CHECK_LIB(posix4, sem_trywait,  [], AC_MSG_ERROR([Could not find sem_trywait]))
					AC_CHECK_LIB(posix4, sem_getvalue, [], AC_MSG_ERROR([Could not find sem_getvalue]))
					SEMAPHORE_LIB=-lposix4
				]
			)
		]
	)
	AC_SUBST([SEMAPHORE_LIB])

	AC_CHECK_HEADERS([fcntl.h sys/stat.h])
])
