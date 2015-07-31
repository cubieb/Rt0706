#ifndef _Crack_h_
#define _Crack_h_

#include "SystemInclude.h"

CxxBeginNameSpace(Router)

class Cracker
{
public:
    Cracker();

    bool IsArpPacket(const DataFrame& dataFrame) const;
    size_t CalculateClearStream(uchar_t *buf, size_t bufSize, int *weight, const DataFrame& dataFrame) const;

    void Start() const;
    void ReceivePacket(std::shared_ptr<uchar_t> buf, size_t bufSize);

private:
    std::shared_ptr<PktDbWrapper> wrapper;
};

CxxEndNameSpace
#endif