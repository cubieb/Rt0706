#ifndef _Crack_h_
#define _Crack_h_

#include "SystemInclude.h"
#include "PktDbWrapper.h"

CxxBeginNameSpace(Router)

class H802dot11;
class Cracker
{
public:
    Cracker();

    void Start();
    void ReceivePacket(H802dot11* pkt);

private:
    std::shared_ptr<PktDbWrapper<H802dot11>> wrapper;
};

CxxEndNameSpace
#endif