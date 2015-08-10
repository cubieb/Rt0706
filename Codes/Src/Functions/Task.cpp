#include "SystemInclude.h"
#include "Common.h"

#include "Types.h"
#include "MacHeader.h"
#include "Task.h"

using namespace std;
CxxBeginNameSpace(Router)

/**********************class Task**********************/
Task::Task(const Mac& theBssid, const Mac& theOwner, const NotifyFunc& theStateNotify) 
    : bssid(theBssid), owner(theOwner), stateNotify(theStateNotify)
{
    state = &TaskInit::GetInstance();
}

Mac Task::GetBssid() const
{
    return bssid;
}

TaskStates Task::GetState() const
{
    return state->GetState(this);
}

uint_t Task::GetPriority() const
{
    return 100;
}

void Task::Run()
{
    state->Run(this);
}

void Task::Pause()
{
    state->Pause(this);
}

void Task::Receive(const MacHeader& macHeader)
{
    state->Receive(this, macHeader);
}

void Task::ChangeState(TaskState* theState)
{
    state = theState;
}

/**********************class Tasks**********************/
std::pair<Tasks::Iterator, bool> Tasks::Insert(const std::shared_ptr<Task>& task)
{
    pair<Iterator, bool> ret = tasks.insert(make_pair(task->GetBssid(), task));

    return make_pair(Iterator(ret.first), ret.second);
}

Tasks::Iterator Tasks::Begin()
{
    return Iterator(tasks.begin());
}

Tasks::Iterator Tasks::End()    
{
    return Iterator(tasks.end());
}

Tasks::Iterator Tasks::Find(const Mac& bssid)
{
    return Iterator(tasks.find(bssid));
}


/**********************class TaskInit**********************/
TaskStates TaskInit::GetState(const Task *task) const
{
    return TaskStates::Init;
}

void TaskInit::Run(Task *task)
{
    assert(false);
}

void TaskInit::Pause(Task *task)
{
    assert(false);
}

void TaskInit::Receive(Task *task, const MacHeader& macHeader)
{
    if (macHeader.GetTypeBits() == H802dot11Type::ManagementFrameType)
    {
        const ManagementFrame& mgmtFrame = dynamic_cast<const ManagementFrame&>(macHeader);
        if (mgmtFrame.GetEssid().size() != 0 && task->essid.size() == 0)
        {
            task->essid = mgmtFrame.GetEssid();
        }
    }
}

/**********************class TaskWepCapturing**********************/
TaskStates TaskWepCapturing::GetState(const Task *task) const
{
    return TaskStates::WepCapturing;
}

void TaskWepCapturing::Run(Task *task)
{
    assert(false);
}

void TaskWepCapturing::Pause(Task *task)
{
    assert(false);
}

void TaskWepCapturing::Receive(Task *task, const MacHeader& macHeader)
{
}

CxxEndNameSpace