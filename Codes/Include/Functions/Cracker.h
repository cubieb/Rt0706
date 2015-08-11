#ifndef _Crack_h_
#define _Crack_h_

#include "SystemInclude.h"

CxxBeginNameSpace(Router)

class Task;
class Cracker
{
public:
    Cracker();

    void Start() const;
    void ReceivePacket(std::shared_ptr<uchar_t> buf, size_t bufSize);
    void StateChanged(Task&);

private:
    std::shared_ptr<PktDbWrapper> wrapper;
};

CxxEndNameSpace
#endif