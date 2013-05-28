# Special processing of paths depending on whether --prefix,
# --sysconfdir or --localstatedir arguments were given.

AC_DEFUN([ACX_PREFIXHACK],[
	case "$prefix" in
		NONE)
			case "$sysconfdir" in
				'${prefix}/etc')
					sysconfdir=/etc
					ac_configure_args="$ac_configure_args --sysconfdir=$sysconfdir"
					AC_MSG_NOTICE([sysconfdir set to $sysconfdir])
					;;
			esac
			case "$localstatedir" in
				'${prefix}/var')
					localstatedir=/var
					ac_configure_args="$ac_configure_args --localstatedir=$localstatedir"
					AC_MSG_NOTICE([localstate set to $localstatedir])
					;;
			esac
			;;
	esac
])
