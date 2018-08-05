AC_DEFUN([ACX_P11KIT],[
	AC_ARG_ENABLE([p11-kit],
		AC_HELP_STRING([--enable-p11-kit],
			[Enable p11-kit integration (default enabled)]
		),
		[enable_p11kit="${enableval}"],
		[enable_p11kit="yes"]
	)

	AC_ARG_WITH(p11-kit,
		AC_HELP_STRING([--with-p11-kit=PATH],[Specify install path of the p11-kit module, will override path given by pkg-config]),
		[P11KIT_PATH="$withval"],
		[P11KIT_PATH=""]
	)

	AC_MSG_CHECKING(for p11-kit integration)
	if test "x${enable_p11kit}" = "xyes"; then
		AC_MSG_RESULT(yes)
		if test "x${P11KIT_PATH}" = "x"; then
			if test "x${PKG_CONFIG}" != "x" && ${PKG_CONFIG} --exists p11-kit-1; then
				P11KIT_PATH=`${PKG_CONFIG} --variable=p11_module_configs p11-kit-1`
			fi
		fi
		AC_MSG_CHECKING(where to install the p11-kit module)
		AC_MSG_RESULT($P11KIT_PATH)
		if test "x${P11KIT_PATH}" = "x"; then
			AC_MSG_WARN([Missing install path for the p11-kit module, skipping module])
		fi
	else
		AC_MSG_RESULT(no)
	fi

	AC_SUBST(P11KIT_PATH)
	AM_CONDITIONAL([WITH_P11KIT], [test "x${enable_p11kit}" = "xyes" -a "x${P11KIT_PATH}" != "x"])
])
