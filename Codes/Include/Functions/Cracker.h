#ifndef _Crack_h_
#define _Crack_h_

#include "SystemInclude.h"

CxxBeginNameSpace(Router)

class Task;
/**********************class Cracker**********************/
class Cracker
{
public:
    Cracker();

    void ReadPcapFile(const char *fileName);
    void Receive(std::shared_ptr<uchar_t> buf, size_t bufSize);
    void StateHandler(Task&);

private:
    std::shared_ptr<PktDbWrapper> wrapper;
};

CxxEndNameSpace
#endif