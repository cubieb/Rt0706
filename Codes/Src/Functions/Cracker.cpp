#include "SystemInclude.h"
#include "SystemError.h" 
#include "Common.h"
#include "Debug.h"

#include "Pcap.h"
#include "PktDbWrapper.h"
#include "Cracker.h"

using namespace std;
CxxBeginNameSpace(Router)

Cracker::Cracker(): wrapper(new PktDbWrapper<H802dot11>(bind(&Cracker::ReceivePacket, this, placeholders::_1)))
{    
}

void Cracker::Start()
{
    wrapper->Start();
}

void Cracker::ReceivePacket(H802dot11* h802dot11)
{
    
}

CxxEndNameSpace