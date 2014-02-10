/* This code was taken from http://www.fourmilab.ch/random/ where it states that:

   This software is in the public domain. Permission to use, copy, modify, and distribute 
   this software and its documentation for any purpose and without fee is hereby granted, 
   without any conditions or restrictions. This software is provided “as is” without 
   express or implied warranty. */

/* ISO 8859/1 Latin-1 alphabetic and upper and lower case bit vector tables. */

/* LINTLIBRARY */

unsigned char isoalpha[32] = {
    0,0,0,0,0,0,0,0,127,255,255,224,127,255,255,224,0,0,0,0,0,0,0,0,255,255,
    254,255,255,255,254,255
};

unsigned char isoupper[32] = {
    0,0,0,0,0,0,0,0,127,255,255,224,0,0,0,0,0,0,0,0,0,0,0,0,255,255,254,254,
    0,0,0,0
};

unsigned char isolower[32] = {
    0,0,0,0,0,0,0,0,0,0,0,0,127,255,255,224,0,0,0,0,0,0,0,0,0,0,0,1,255,255,
    254,255
};
