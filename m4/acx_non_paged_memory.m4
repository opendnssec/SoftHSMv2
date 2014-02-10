AC_DEFUN([ACX_NON_PAGED_MEMORY],[

	AC_ARG_ENABLE(non-paged-memory,
		AC_HELP_STRING([--disable-non-paged-memory],
			[Disable non-paged memory for secure storage (default enabled)]
		),
		[enable_non_paged_memory="${enableval}"],
		[enable_non_paged_memory="yes"]
	)

	AC_MSG_CHECKING(for non-paged memory for secure storage)

	if test "x${enable_non_paged_memory}" = "xyes"; then
		AC_MSG_RESULT(enabled)
		AC_DEFINE_UNQUOTED(
			[SENSITIVE_NON_PAGE],
			[],
			[Non-paged memory for secure storage]
		)
		AC_CHECK_HEADERS([sys/mman.h])

		AC_MSG_CHECKING(the maximum size that may be locked into memory)
		MLOCK_SIZE="`ulimit -l`"
		AC_MSG_RESULT($MLOCK_SIZE)

		if test "x${MLOCK_SIZE}" != "xunlimited"; then
			AC_MSG_WARN([
======================================================================
SoftHSM has been configured to store sensitive data in non-page RAM
(i.e. memory that is not swapped out to disk). This is the default and
most secure configuration. Your system, however, is not configured to
support this model in non-privileged accounts (i.e. user accounts).

You can check the setting on your system by running the following
command in a shell:

	ulimit -l

If this does not return "unlimited" and you plan to run SoftHSM from
non-privileged accounts then you should edit the configuration file
/etc/security/limits.conf (on most systems).

You will need to add the following lines to this file:

#<domain>	<type>		<item>		<value>
*		-		memlock		unlimited

Alternatively, you can elect to disable this feature of SoftHSM by
re-running configure with the option "--disable-non-paged-memory". 
Please be advised that this may seriously degrade the security of 
SoftHSM.
======================================================================])
		fi
	else
		AC_MSG_RESULT(disabled)
	fi
])
