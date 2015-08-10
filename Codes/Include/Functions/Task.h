#ifndef _Task_h_
#define _Task_h_

#include "SystemInclude.h"
CxxBeginNameSpace(Router)

enum class TaskStates
{
    Init, /* init state */
    WepCapturing, 
    WpaCapturing, 
    WpaWaitting,  /* only wpa */
    WpaRunning,   /* only wpa */
    Successed, 
    Failed
};

class MacHeader;
class TaskState;
/**********************class Task**********************/
class Task
{
public:
    typedef std::function<void(Task& task)> NotifyFunc;
    Task(const Mac& theBssid, const Mac& theOwner, const NotifyFunc& theStateNotify);

    Mac GetBssid() const;
    TaskStates GetState() const;
    uint_t GetPriority() const;
    void Run();
    void Pause();
    void Receive(const MacHeader& macHeader);

private:
    friend class TaskState;
    friend class TaskInit;
    void ChangeState(TaskState* theState);
    TaskState *state;

private:
    Task() {}
    Mac    bssid;
    Mac    owner; /* if owner == myMac, this is a local task */
    std::string essid;
    NotifyFunc stateNotify;
};

/**********************class Tasks**********************/
class Tasks
{
public:
    typedef MapIterator<std::map<Mac, std::shared_ptr<Task>>::iterator> Iterator;
    typedef MapIterator<std::map<Mac, std::shared_ptr<Task>>::const_iterator> ConstIterator;

    /* there are at most 5 psw task existing at the same time, if the new task has higher 
       priority,  one less priority task will be deleted.
     */
    std::pair<Iterator, bool> Insert(const std::shared_ptr<Task>&);
    Iterator Begin();
    Iterator End();
    Iterator Find(const Mac& bssid);
    //Iterator Erase(Iterator& whr);

    static Tasks& GetInstance()
    {
        static Tasks instance;
        return instance;
    }

private:
    Tasks() {}
    std::map<Mac, std::shared_ptr<Task>> tasks;
};

/**********************class TaskState**********************/
class TaskState
{
public:
    virtual TaskStates GetState(const Task *task) const = 0;
    virtual void Run(Task *task) = 0;
    virtual void Pause(Task *task) = 0;
    virtual void Receive(Task *task, const MacHeader& macHeader) = 0;
};

/**********************class TaskInit**********************/
class TaskInit: public TaskState
{
public:
    TaskStates GetState(const Task *task) const;
    void Run(Task *task);
    void Pause(Task *task);
    void Receive(Task *task, const MacHeader& macHeader);

    static TaskInit& GetInstance()
    {
        static TaskInit instance;
        return instance;
    }
};

/**********************class TaskWepCapturing**********************/
class TaskWepCapturing: public TaskState
{
public:
    TaskStates GetState(const Task *task) const;
    void Run(Task *task);
    void Pause(Task *task);
    void Receive(Task *task, const MacHeader& macHeader);

    static TaskInit& GetInstance()
    {
        static TaskInit instance;
        return instance;
    }
};

CxxEndNameSpace
#endif