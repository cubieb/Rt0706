#ifndef _Task_h_
#define _Task_h_

CxxBeginNameSpace(Router)

enum class TaskStates
{
    Init, /* init state */
    WepCapturing, 
    TkipCapturing, 
    TkipWaitting,  /* only tkip */
    TkipRunning,   /* only tkip */
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

    const Mac& GetBssid() const;
    TaskStates GetState() const;
    uint_t GetPriority() const;

    void Run();
    void Pause();
    void Receive(const MacHeader& macHeader);

    /* the following function is provided just for debug */
    void Put(std::ostream& os) const;

    friend class TaskState;
    friend class TaskInit;
    friend class TaskCapturing;
    friend class TaskWepCapturing;
    friend class TaskTkipCapturing;

private:
    void ChangeState(TaskState* theState);
    Mac  bssid;
    std::string essid;
    Mac  owner; /* if owner == myMac, this is a local task */    
    TaskState *state;
    /* when success, notify the craker parent. */
    NotifyFunc stateNotify;
    std::shared_ptr<PtwState> ptwState;
};

inline std::ostream& operator << (std::ostream& os, const Task& task)
{
    task.Put(os);
    return os;
}

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
    Iterator Find(const Mac& bssid);
    Iterator begin();
    Iterator end();

    /* the following function is provided just for debug */
    void Put(std::ostream& os) const;

    static Tasks& GetInstance()
    {
        static Tasks instance;
        return instance;
    }

private:
    Tasks() {}
    std::map<Mac, std::shared_ptr<Task>> tasks;
};

inline std::ostream& operator << (std::ostream& os, const Tasks& tasks)
{
    tasks.Put(os);
    return os;
}

/**********************class TaskState**********************/
class TaskState
{
public:
    virtual TaskStates GetState(const Task *task) const = 0;
    virtual void Run(Task *task) { assert(false); }
    virtual void Pause(Task *task) {  assert(false); }

    void Receive(Task *task, const MacHeader& macHeader);
    virtual void DoReceive(Task *task, const MacHeader& macHeader) = 0;
};

/**********************class TaskInit**********************/
class TaskInit: public TaskState
{
public:
    TaskStates GetState(const Task *task) const;
    void DoReceive(Task *task, const MacHeader& macHeader);

    static TaskInit& GetInstance()
    {
        static TaskInit instance;
        return instance;
    }
};

/**********************class TaskCapturing**********************/
class TaskCapturing: public TaskState
{
public:
    TaskStates GetState(const Task *task) const;
    void DoReceive(Task *task, const MacHeader& macHeader);

    static TaskCapturing& GetInstance()
    {
        static TaskCapturing instance;
        return instance;
    }
};

/**********************class TaskWepCapturing**********************/
class TaskWepCapturing: public TaskState
{
public:
    TaskWepCapturing();

    TaskStates GetState(const Task *task) const;
    void DoReceive(Task *task, const MacHeader& macHeader);

    static TaskWepCapturing& GetInstance()
    {
        static TaskWepCapturing instance;
        return instance;
    }

private:
    bool IsArpPacket(const MacHeader& dataFrame) const;
    size_t CalculateClearStream(uchar_t *buf, size_t bufSize, int *weight, const MacHeader& dataFrame) const;
    void GuessKeyBytes(uchar_t *iv, size_t ivSize, uchar_t *key, uchar_t *result, size_t resultSize);
    void Check();
};

/**********************class TaskTkipCapturing**********************/
class TaskTkipCapturing: public TaskState
{
public:
    TaskStates GetState(const Task *task) const;
    void DoReceive(Task *task, const MacHeader& macHeader);

    static TaskTkipCapturing& GetInstance()
    {
        static TaskTkipCapturing instance;
        return instance;
    }
};

CxxEndNameSpace
#endif