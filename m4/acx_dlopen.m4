AC_DEFUN([ACX_DLOPEN],[
  AC_CHECK_FUNC(dlopen, [AC_DEFINE(HAVE_DLOPEN,1,[Define if you have dlopen])],
  [
    AC_CHECK_LIB([dl],[dlopen], 
      [AC_DEFINE(HAVE_DLOPEN,1,[Define if you have dlopen])
      LIBS="$LIBS -ldl"],
      [AC_CHECK_FUNC(LoadLibrary, 
        [if test $ac_cv_func_LoadLibrary = yes; then
          AC_DEFINE(HAVE_LOADLIBRARY, 1, [Whether LoadLibrary is available])
        fi
        ], [AC_MSG_ERROR(No dynamic library loading support)]
      )]
    )
  ])
])
