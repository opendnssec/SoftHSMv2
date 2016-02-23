/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 getpw.cpp

 Helper function to get a password from the user
 *****************************************************************************/

#include <config.h>
#include "getpw.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <termios.h>
#include <signal.h>
#endif

#ifndef _WIN32
// Remember the signal number
static volatile sig_atomic_t signo;

void sighandler(int s)
{
	signo = s;
}
#endif

int getpin(const char* prompt, char* buffer, size_t size)
{
	if (prompt == NULL || buffer == NULL || size < 1)
		return -1;

	printf("%s", prompt);

#ifdef _WIN32
	HANDLE hstdin = GetStdHandle(STD_INPUT_HANDLE);
	DWORD mode;

	// Save current console mode
	if (!GetConsoleMode(hstdin, &mode))
		return -1;

	// Update the console mode
	if (hstdin == INVALID_HANDLE_VALUE || !(SetConsoleMode(hstdin, ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT)))
		return -1;
#else
	struct termios new_attr, old_attr;

	// Get current terminal attributes
	if (tcgetattr(STDIN_FILENO, &old_attr) < 0)
		return -1;

	// Save the mode flags
	new_attr = old_attr;

	// Update the mode flags
	new_attr.c_lflag &= ~ICANON;
	new_attr.c_lflag &= ~ECHO;

	// Handle the SIGINT signal
	signo = 0;
	struct sigaction osa, sa;
	sigaction(SIGINT, NULL, &osa);
	if (osa.sa_handler != SIG_IGN)
	{
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;
		sa.sa_handler = sighandler;
		sigaction(SIGINT, &sa, &osa);
        }

	// Set the new terminal attributes
	if (tcsetattr(STDIN_FILENO, 0, &new_attr) < 0)
		return -1;
#endif

	size_t nread = 0;
	int ch = 0;
	while ((ch = getchar()) != '\n' && ch != EOF)
	{
		// Check buffer size
		if ((nread+2) > size)
			continue;

		putchar('*');
		buffer[nread] = ch;
		nread++;
	}

	putchar('\n');
	buffer[nread] = '\0';

#ifdef _WIN32
	// Restore the console mode
	if (!SetConsoleMode(hstdin, mode))
		return -1;
#else
	// Restore terminal
	if (tcsetattr(STDIN_FILENO, 0, &old_attr) < 0)
		return -1;

	// Restore the signal
	sigaction(SIGINT, &osa, NULL);
	if (signo)
		raise(signo);
#endif

	return nread;
}

// Get a password from the user
int getPW(char* pin, char* newPIN, CK_ULONG userType)
{
	char password1[MAX_PIN_LEN+1];
	char password2[MAX_PIN_LEN+1];
	size_t size = MAX_PIN_LEN+1;
	int length = 0;

	// Check if the user has provided a password
	if (pin)
	{
		length = strlen(pin);
		// Save the PIN if it has the correct length
		if (length >= MIN_PIN_LEN && length <= MAX_PIN_LEN)
			memcpy(password1, pin, length+1);
	}

	while (length < MIN_PIN_LEN || length > MAX_PIN_LEN)
	{
		if (userType == CKU_SO)
		{
			printf("=== SO PIN (%i-%i characters) ===\n",
				MIN_PIN_LEN, MAX_PIN_LEN);
			length = getpin("Please enter SO PIN: ",
					password1, size);
		}
		else
		{
			printf("=== User PIN (%i-%i characters) ===\n",
				MIN_PIN_LEN, MAX_PIN_LEN);
			length = getpin("Please enter user PIN: ",
					password1, size);
		}

		if (length < 0)
			return 1;
		if (length < MIN_PIN_LEN || length > MAX_PIN_LEN)
		{
			fprintf(stderr, "ERROR: The length of the PIN is out of range.\n");
			length = 0;
			continue;
		}

		if (userType == CKU_SO)
		{
			length = getpin("Please reenter SO PIN: ",
					password2, size);
		}
		else
		{
			length = getpin("Please reenter user PIN: ",
					password2, size);
		}

		if (length < 0)
			return 1;
		if (strcmp(password1, password2))
		{
			fprintf(stderr, "ERROR: The entered PINs are not equal.\n");
			length = 0;
			continue;
		}
	}

	memcpy(newPIN, password1, length+1);
	return 0;
}
