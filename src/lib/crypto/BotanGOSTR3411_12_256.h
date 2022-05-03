#ifndef BOTANGOSTR3411_12_256_H
#define BOTANGOSTR3411_12_256_H

#include "BotanHashAlgorithm.h"

class BotanGOSTR3411_12_256 : public BotanHashAlgorithm
{
    virtual int getHashSize();
protected:
    virtual const char* getHashName() const;
};

#endif // BOTANGOSTR3411_12_256_H
