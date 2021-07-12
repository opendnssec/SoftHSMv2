#ifndef BOTANGOSTR3411_12_512_H
#define BOTANGOSTR3411_12_512_H

#include "BotanHashAlgorithm.h"

class BotanGOSTR3411_12_512 : public BotanHashAlgorithm
{
    virtual int getHashSize();
protected:
    virtual const char* getHashName() const;
};

#endif // BOTANGOSTR3411_12_512_H
