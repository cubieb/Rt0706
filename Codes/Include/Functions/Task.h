#ifndef _Task_h_
#define _Task_h_

CxxBeginNameSpace(Router)

class MacHeader;
class TaskState;
/**********************class Task**********************/
class Task: public std::enable_shared_from_this<Task>
{
public:
    typedef std::function<void(Task& task)> StateHandler;
    Task(const Mac& theBssid, const Mac& theOwner, const StateHandler& theStateHandler);
    //beause shared_from_this() can't be called in constructor, we have to 
    //init TaskState in Init().
    void Init(); 

    const Mac& GetBssid() const;
    TaskStateEnum GetState() const;
    uint_t GetPriority() const;

    void Run();
    void Pause();
    void Receive(const MacHeader& macHeader);
    void ChangeState(TaskState* newState);

    /* the following function is provided just for debug */
    void Put(std::ostream& os) const;

private:
    Mac  bssid;    
    Mac  owner; /* if owner == myMac, this is a local task */      
    /* when success, notify the parent. */
    StateHandler stateHandler;
    std::shared_ptr<TaskState> state;
    std::string essid;
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

CxxEndNameSpace
#endif