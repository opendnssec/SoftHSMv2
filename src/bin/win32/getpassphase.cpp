/* WIN32 getpassphrase */

#include <config.h>
#include <stdio.h>

char *
getpassphrase(const char *prompt) {
	static char buf[128];
	HANDLE h;
	DWORD cc, mode;
	int cnt;

	h = GetStdHandle(STD_INPUT_HANDLE);
	fputs(prompt, stderr);
	fflush(stderr);
	fflush(stdout);
	FlushConsoleInputBuffer(h);
	GetConsoleMode(h, &mode);
	SetConsoleMode(h, ENABLE_PROCESSED_INPUT);

	for (cnt = 0; cnt < sizeof(buf) - 1; cnt++)
	{
		ReadFile(h, buf + cnt, 1, &cc, NULL);
		if (buf[cnt] == '\r')
			break;
		fputc('*', stdout);
		fflush(stderr);
		fflush(stdout);
	}

	SetConsoleMode(h, mode);
	buf[cnt] = '\0';
	fputs("\n", stderr);
	return (buf);
}
