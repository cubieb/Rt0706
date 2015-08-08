#ifndef _Task_h_
#define _Task_h_

#include "SystemInclude.h"
#include "AccessPoint.h"
CxxBeginNameSpace(Router)

enum class TaskState
{
    Capturing = 0, /* init state */
    Running,   /* only wpa */
    Waitting,  /* only wpa */
    Successed, 
    Failed
};

class Task
{
public:
    Mac  id;

    void StartTask();
    void StopTask();
    void Receive(std::shared_ptr<uchar_t> buf, size_t bufSize);

private:
    uint_t    priority;
    TaskState state;
    Mac       owner; /* if owner == myMac, this is a local task */
    
};

class WepTask: public Task
{

};

class WpaTask: public Task
{
private:
    void DistributeTask();
};


CxxEndNameSpace
#endif