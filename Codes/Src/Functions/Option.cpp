#include "SystemInclude.h"
#include "Common.h"
#include "Option.h"

CxxBeginNameSpace(Router)
using namespace std;

Option::Option()
{
    doPtw = false;
}

bool Option::DoForceBssid()
{
    return false;
}

Mac Option::GetBssid()
{
    Mac bssid((const uint8_t*)"\x00\x12\xbf\x12\x32\x29");
    return bssid;
}

bool Option::DoPtw() const
{
    return doPtw;
}

Option& Option::GetInstance()
{
    static Option instance;
    return instance;
}

CxxEndNameSpace