#ifndef _StateMachine_h_
#define _StateMachine_h_
CxxBeginNameSpace(Router)

#include "Types.h"

class MacHeader;
class Task;
/**********************class TaskState**********************/
class TaskState
{
public:
    TaskState(std::shared_ptr<Task>& theTask): task(theTask) {}

    virtual TaskStateEnum GetState() const = 0;
    virtual void Run() { assert(false); }
    virtual void Pause() { assert(false); }

    std::shared_ptr<TaskState> Receive(const MacHeader& macHeader);

protected:
    virtual std::shared_ptr<TaskState> DoReceive(const MacHeader& macHeader) = 0;

protected:
    std::shared_ptr<Task> task;
};

/**********************class TaskInit**********************/
class TaskInit: public TaskState
{
public:
    TaskInit(std::shared_ptr<Task>& task): TaskState(task) {}

    TaskStateEnum GetState() const;
    std::shared_ptr<TaskState> DoReceive(const MacHeader& macHeader);
};

/**********************class TaskCapturing**********************/
class TaskCapturing: public TaskState
{
public:
    TaskCapturing(std::shared_ptr<Task>& task): TaskState(task) {}

    TaskStateEnum GetState() const;
    std::shared_ptr<TaskState> DoReceive(const MacHeader& macHeader);
};

/**********************class TaskWepCapturing**********************/
class TaskWepCapturing: public TaskState
{
public:
    enum: uint_t
    { 
        WepMaxKeySize = 24,
        WepIvTableSize = 0xFFFFFF /* wep iv fields is 3 bytes, so the table size is 2**24 */
    };
    
    TaskWepCapturing(std::shared_ptr<Task>& task, const std::shared_ptr<MacPdu>& macPdu);

    TaskStateEnum GetState() const;
    std::shared_ptr<TaskState> DoReceive(const MacHeader& macHeader);

private:
    bool IsArpPacket(const MacHeader& dataFrame) const;
    size_t CalculateClearStream(uchar_t *buf, size_t bufSize, const MacHeader& dataFrame) const;
    void GuessKeyBytes(uchar_t *iv, size_t ivSize, uchar_t *key, uchar_t *result, size_t resultSize);
    void Check();
    bool IsCorrect(uchar_t *fullKey);

private:
    std::bitset<WepIvTableSize> IvBits;
    PtwTable ptwTable;
    uint_t   pktNumber;
    const std::shared_ptr<MacPdu> macPdu;
};

/**********************class TaskTkipCapturing**********************/
class TaskTkipCapturing: public TaskState
{
public:
    TaskTkipCapturing(std::shared_ptr<Task>& task): TaskState(task) {}

    TaskStateEnum GetState() const;
    std::shared_ptr<TaskState> DoReceive(const MacHeader& macHeader);
};

CxxEndNameSpace
#endif