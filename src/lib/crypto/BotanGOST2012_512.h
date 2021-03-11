#ifndef BOTANGOST2012_512_H
#define BOTANGOST2012_512_H

#include "BotanGOST.h"

class BotanGOST2012_512 : public BotanGOST
{
public:
	BotanGOST2012_512() = default;

	bool generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* rng);
};

#endif // BOTANGOST2012_512_H
