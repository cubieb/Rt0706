#include "SystemInclude.h"
#include "Common.h"
#include "Eapol.h"
#include "Station.h"
CxxBeginNameSpace(Router)

St::St(const Mac& theMac): mac(theMac)
{
}

const Mac& St::GetMac() const
{
    return mac;
}

CxxEndNameSpace