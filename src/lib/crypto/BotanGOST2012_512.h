#ifndef BOTANGOST2012_512_H
#define BOTANGOST2012_512_H

#include "BotanGOST.h"

#ifdef WITH_GOST

class BotanGOST2012_512 : public BotanGOST
{
public:
	BotanGOST2012_512() = default;

	bool generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* rng);

	// Signing functions
	virtual bool signInit(PrivateKey* privateKey, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0);

	// Verification functions
	virtual bool verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism, const void* param = NULL, const size_t paramLen = 0);
};

#endif

#endif // BOTANGOST2012_512_H
