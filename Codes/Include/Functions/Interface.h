
#ifndef _Interface_h_
#define _Interface_h_

#include "SystemInclude.h"

#include "Types.h"

class MacHeader;
class Task;

/**********************class Interface**********************/
class Interface
{
public:
    Interface() {}
    virtual ~Interface() {}

    //virtual TaskState GetState() const = 0;
    virtual void Run() { assert(false); }
    virtual void Pause() { assert(false); }
    virtual Interface* Receive(const MacHeader& macHeader) = 0;
};

#endif