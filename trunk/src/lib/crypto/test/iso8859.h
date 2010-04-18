/* This code was taken from http://www.fourmilab.ch/random/ where it states that:

   This software is in the public domain. Permission to use, copy, modify, and distribute 
   this software and its documentation for any purpose and without fee is hereby granted, 
   without any conditions or restrictions. This software is provided “as is” without 
   express or implied warranty. */

/* ISO 8859/1 Latin-1 "ctype" macro replacements. */

extern unsigned char isoalpha[32], isoupper[32], isolower[32];

#define isISOspace(x)	((isascii(((unsigned char) (x))) && isspace(((unsigned char) (x)))) || ((x) == 0xA0))
#define isISOalpha(x)	((isoalpha[(((unsigned char) (x))) / 8] & (0x80 >> ((((unsigned char) (x))) % 8))) != 0)
#define isISOupper(x)	((isoupper[(((unsigned char) (x))) / 8] & (0x80 >> ((((unsigned char) (x))) % 8))) != 0)
#define isISOlower(x)	((isolower[(((unsigned char) (x))) / 8] & (0x80 >> ((((unsigned char) (x))) % 8))) != 0)
#define isISOprint(x)   ((((x) >= ' ') && ((x) <= '~')) || ((x) >= 0xA0))
#define toISOupper(x)   (isISOlower(x) ? (isascii(((unsigned char) (x))) ?  \
                            toupper(x) : (((((unsigned char) (x)) != 0xDF) && \
                            (((unsigned char) (x)) != 0xFF)) ? \
			    (((unsigned char) (x)) - 0x20) : (x))) : (x))
#define toISOlower(x)   (isISOupper(x) ? (isascii(((unsigned char) (x))) ?  \
                            tolower(x) : (((unsigned char) (x)) + 0x20)) \
			    : (x))
