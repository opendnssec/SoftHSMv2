#ifndef BOTANGOST2012_H
#define BOTANGOST2012_H

#include "BotanGOST.h"

class BotanGOST2012 : public BotanGOST
{
public:
        BotanGOST2012() = default;

        bool generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* rng);
};

#endif // BOTANGOST2012_H
