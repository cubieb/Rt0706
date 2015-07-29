#ifndef _Crack_h_
#define _Crack_h_

#include "SystemInclude.h"
#include "PktDbWrapper.h"

CxxBeginNameSpace(Router)

class Cracker
{
public:
    Cracker();

    void Start();
    void ReceivePacket(std::shared_ptr<uchar_t> buf, size_t bufSize);

private:
    std::shared_ptr<PktDbWrapper> wrapper;
};

CxxEndNameSpace
#endif