#include <botan/botan.h>
#include <botan/version.h>
int main()
{
        using namespace Botan;

#if BOTAN_VERSION_CODE >= BOTAN_VERSION_CODE_FOR(2,3,0)
        return 0;
#endif
        return 1;
}
