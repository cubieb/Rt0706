#include "SystemInclude.h"
#include "Common.h"

#include "Types.h"
#include "MacHeader.h"
#include "SecurityHeader.h"
#include "PtwLib.h"
#include "Rc4.h"
#include "StateMachine.h"
#include "Task.h"

using namespace std;
CxxBeginNameSpace(Router)

/**********************class Task**********************/
Task::Task(const Mac& theBssid, const Mac& theOwner, const StateHandler& theStateHandler) 
    : bssid(theBssid), owner(theOwner), stateHandler(theStateHandler)
{}

void Task::Init()
{
    auto ptr = shared_from_this();
    state.reset(new TaskInit(ptr));
}

const Mac& Task::GetBssid() const
{
    return bssid;
}

TaskStateEnum Task::GetState() const
{
    return state->GetState();
}

uint_t Task::GetPriority() const
{
    return 100;
}

void Task::Run()
{
    state->Run();
}

void Task::Pause()
{
    state->Pause();
}

void Task::Receive(const MacHeader& macHeader)
{
    if (macHeader.GetTypeBits() == H802dot11Type::ManagementFrameType
        && essid.size() == 0)
    {
        const ManagementFrame& mgmtFrame = dynamic_cast<const ManagementFrame&>(macHeader);
        essid = mgmtFrame.GetEssid();
    }

    while (true)
    {
        auto newState = state->Receive(macHeader);
        if (newState == nullptr)
            break;

        state = newState;
    }
}

void Task::ChangeState(TaskState* newState)
{
    state.reset(newState);
}

void Task::Put(std::ostream& os) const
{
    os << "Owner = " << owner << ", Bssid = " << bssid << ", Essid = " << essid
        << endl;
}

/**********************class Tasks**********************/
std::pair<Tasks::Iterator, bool> Tasks::Insert(const std::shared_ptr<Task>& task)
{
    pair<Iterator, bool> ret = tasks.insert(make_pair(task->GetBssid(), task));

    return make_pair(Iterator(ret.first), ret.second);
}

void Tasks::Put(std::ostream& os) const
{
    for (auto iter = tasks.begin(); iter != tasks.end(); ++iter)
    {
        os << *(iter->second);
    }
}

Tasks::Iterator Tasks::begin()
{
    return Iterator(tasks.begin());
}

Tasks::Iterator Tasks::end()    
{
    return Iterator(tasks.end());
}

Tasks::Iterator Tasks::Find(const Mac& bssid)
{
    return Iterator(tasks.find(bssid));
}

CxxEndNameSpace