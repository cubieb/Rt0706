#ifndef _Crack_h_
#define _Crack_h_

#include "SystemInclude.h"

CxxBeginNameSpace(Router)

class Cracker
{
public:
    Cracker();

    bool IsArpPacket(const H802dot11& dataFrame) const;
    size_t CalculateClearStream(uchar_t *buf, size_t bufSize, int *weight, const H802dot11& dataFrame) const;
    void GuessKeyBytes(uchar_t *iv, size_t ivSize, uchar_t *key, uchar_t *result, size_t resultSize);

    void Start() const;
    void ReceivePacket(std::shared_ptr<uchar_t> buf, size_t bufSize);

private:
    std::shared_ptr<PktDbWrapper> wrapper;
    std::shared_ptr<PswState> state;
};



CxxEndNameSpace
#endif