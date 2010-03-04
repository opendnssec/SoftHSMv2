/* This code was taken from http://www.fourmilab.ch/random/ where it states that:

   This software is in the public domain. Permission to use, copy, modify, and distribute 
   this software and its documentation for any purpose and without fee is hereby granted, 
   without any conditions or restrictions. This software is provided “as is” without 
   express or implied warranty. */

/*
	ENT  --  Entropy calculation and analysis of putative
		 random sequences.

        Designed and implemented by John "Random" Walker in May 1985.

	Multiple analyses of random sequences added in December 1985.

	Bit stream analysis added in September 1997.

	Terse mode output, getopt() command line processing,
	optional stdin input, and HTML documentation added in
	October 1998.
	
	Documentation for the -t (terse output) option added
	in July 2006.
	
	Replaced table look-up for chi square to probability
	conversion with algorithmic computation in January 2008.

	For additional information and the latest version,
	see http://www.fourmilab.ch/random/

*/

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#else
#include <unistd.h>
#endif

#include "iso8859.h"
#include "randtest.h"

#define UPDATE  "January 28th, 2008"

#define FALSE 0
#define TRUE  1

#ifdef M_PI
#define PI	 M_PI
#else
#define PI	 3.14159265358979323846
#endif

extern double pochisq(const double ax, const int df);

/*  Main program  */

void doEnt
(
	unsigned char* data, 
	size_t len, 
	double* pEntropy,
	double* pChiProbability,
	double* pArithMean,
	double* pMontePi,
	double* pSerialCorrelation
)
{
	size_t s;
	long ccount[256];	      /* Bins to count occurrences of values */
	double montepi, chip,
	       scc, ent, mean, chisq;

	/* Initialise for calculations */

	rt_init(FALSE);

	/* Scan input file and count character occurrences */

	for (s = 0; s < len; s++)
	{
	   unsigned char ocb = data[s];

	   ccount[ocb]++;	      /* Update counter for this bin */
	   rt_add(&ocb, 1);
	}

	/* Complete calculation and return sequence metrics */

	rt_end(&ent, &chisq, &mean, &montepi, &scc);

	/* Calculate probability of observed distribution occurring from
	   the results of the Chi-Square test */

    	chip = pochisq(chisq, 255);

	/* Print bin counts if requested */

	/* Return calculated results */

	*pEntropy = ent;
	*pChiProbability = chip;
	*pArithMean = mean;
	*pMontePi = montepi;
	*pSerialCorrelation = scc;
}
