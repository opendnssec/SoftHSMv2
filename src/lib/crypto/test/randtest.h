/* This code was taken from http://www.fourmilab.ch/random/ where it states that:

   This software is in the public domain. Permission to use, copy, modify, and distribute 
   this software and its documentation for any purpose and without fee is hereby granted, 
   without any conditions or restrictions. This software is provided “as is” without 
   express or implied warranty. */

/*  Random test function prototypes  */

extern void rt_init(int binmode);
extern void rt_add(void *buf, int bufl);
extern void rt_end(double *r_ent, double *r_chisq, double *r_mean,
                   double *r_montepicalc, double *r_scc);
