#include "SystemInclude.h"
#include "Common.h"

#include "Types.h"
#include "MacHeader.h"
#include "SecurityHeader.h"
#include "PtwLib.h"
#include "Rc4.h"
#include "Task.h"

using namespace std;
CxxBeginNameSpace(Router)

/**********************class Task**********************/
Task::Task(const Mac& theBssid, const Mac& theOwner, const NotifyFunc& theStateNotify) 
    : bssid(theBssid), owner(theOwner), stateNotify(theStateNotify), ptwState(nullptr)
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

/**********************class TaskState**********************/
void TaskState::Receive(Task *task, const MacHeader& macHeader)
{
    if (macHeader.GetTypeBits() == H802dot11Type::ControlFrameType
        || macHeader.GetBssid().IsBroadcast())
    {
        return;
    }

    if (macHeader.GetTypeBits() == H802dot11Type::ManagementFrameType)
    {
        const ManagementFrame& mgmtFrame = dynamic_cast<const ManagementFrame&>(macHeader);
        if (mgmtFrame.GetEssid().size() != 0 && task->essid.size() == 0)
        {
            task->essid = mgmtFrame.GetEssid();
        }
    }
    DoReceive(task, macHeader);
}

/**********************class TaskInit**********************/
TaskStates TaskInit::GetState(const Task *task) const
{
    return TaskStates::Init;
}

void TaskInit::DoReceive(Task *task, const MacHeader& macHeader)
{
    TaskCapturing& state = TaskCapturing::GetInstance();
    task->ChangeState(&state);
    state.DoReceive(task, macHeader); 
}

/**********************class TaskCapturing**********************/
TaskStates TaskCapturing::GetState(const Task *task) const
{
    return TaskStates::WepCapturing;
}

void TaskCapturing::DoReceive(Task *task, const MacHeader& macHeader)
{
    if (macHeader.GetWepBit() == 0)
    {
        return; //line 1410, aircrack-ng.c, aircrack-ng-1.2-rc2
    }

    shared_ptr<SecurityHeader> protectedMpdu(CreateSecurityHeader(macHeader));
    if (protectedMpdu->GetCryptMode() == CryptMode::Wep)
    {
        TaskWepCapturing& state = TaskWepCapturing::GetInstance();
        task->ChangeState(&state);
        
        task->ptwState.reset(new PswState);
        size_t i, j;
        for (i = 0; i < WepMaxKeySize; ++i)
        {
            for (j = 0; j < 256; ++j)
                task->ptwState->table[i][j] = 0;
        }
        state.DoReceive(task, macHeader); 
    }
    else
    {
        TaskTkipCapturing& state = TaskTkipCapturing::GetInstance();
        task->ChangeState(&state);
        state.DoReceive(task, macHeader); 
    }
}

/**********************class TaskWepCapturing**********************/
TaskWepCapturing::TaskWepCapturing()
{}

TaskStates TaskWepCapturing::GetState(const Task *task) const
{
    return TaskStates::WepCapturing;
}

void TaskWepCapturing::DoReceive(Task *task, const MacHeader& macHeader)
{
    if (macHeader.GetTypeBits() != DataFrameType)
        return ;

    /* line 1424, if( h80211[z] != h80211[z + 1] || h80211[z + 2] != 0x03 ),
       aircrack-ng.c, aircrack-ng-1.2-rc2
       p = dataFrame.GetFrameBody()
       if (p[0] = 0xaa, p[1] = 0xaa, p[2] = 0x03) => logical link control header, so there is not a wep parameter.
       else there must be a wep parameter flowing the 802.11 mac header.
    */
    uchar_t *wepIv = macHeader.GetFrameBodyPtr();

    /* check the WEP key index. Data Frame, WEP Parameter */
    /* do nothing. */
    uchar_t clear[512] = {0};
    int     weight[16];

    memset(weight, 0, sizeof(weight));
	memset(clear, 0, sizeof(clear));

    size_t i, clearSize; 
    clearSize = CalculateClearStream(clear, sizeof(clear), weight, macHeader);

    shared_ptr<SecurityHeader> protectedMpdu(CreateSecurityHeader(macHeader));
    uchar_t *snapHeader = wepIv + protectedMpdu->GetHeaderSize();
    for (i = 0; i < clearSize; i++)
    {
        /* calculate KSA of round i+3 */
        clear[i] = clear[i] ^ snapHeader[i];
    }

    /* Start PSW process. */
    uint_t ivId;
    ivId = (wepIv[0] << 16) | (wepIv[1] << 8) | (wepIv[2]);
    if (task->ptwState->IvBits.test(ivId))
        return;

    task->ptwState->IvBits.set(ivId);
    uint8_t result[WepMaxKeySize];
    GuessKeyBytes(wepIv, protectedMpdu->GetIvSize(), clear, result, WepMaxKeySize);
    for (i = 0; i < WepMaxKeySize; ++i)
    {
        task->ptwState->table[i][result[i]]++;
    }
}

bool TaskWepCapturing::IsArpPacket(const MacHeader& dataFrame) const
{
    int size = CalcLayer3DataSize(dataFrame);
    int arpSize = 8 + 8 + 10*2;  //???
        
    /* remove non BROADCAST frames? could be anything, but
        * chances are good that we got an arp response tho.   
        */

    if (size == arpSize || size == 54)
        return true;

    return false;
}

/* weight is used for guesswork in PTW.  Can be null if known_clear is not for
 * PTW, but just for getting known clear-text.
 */
size_t TaskWepCapturing::CalculateClearStream(uchar_t *buf, size_t bufSize, int *weight, const MacHeader& dataFrame) const
{
    uchar_t *ptr = (uchar_t*)buf;
    int num = 1;

    if(IsArpPacket(dataFrame)) /*arp*/
    {
        ptr += MemCopy(ptr, bufSize, LlcSnap::GetLlcSnapArp(), LlcSnap::GetSize());
        bufSize = bufSize - LlcSnap::GetSize();

        /* arp header */
        ptr += MemCopy(ptr, bufSize, "\x00\x01\x08\x00\x06\x04", 6);
        bufSize = bufSize - 6;

        /* type of arp */
        if (dataFrame.GetDstMac().Compare((uchar_t*)"\xff\xff\xff\xff\xff\xff") == 0)
            ptr += MemCopy(ptr, bufSize, "\x00\x01", 2);
        else
            ptr += MemCopy(ptr, bufSize, "\x00\x02", 2);
        bufSize = bufSize - 2;

        /* src mac */
        ptr += MemCopy(ptr, bufSize, dataFrame.GetSrcMac().GetPtr(), 6);
  
        if (weight != nullptr)
            weight[0] = 256;

        return (ptr - buf); 
    }

    return 0;
}

/*
Parameter:
    key: the X of formula 26. "kleins_and_ptw_attacks_on_wep.pdf"
*/
void TaskWepCapturing::GuessKeyBytes(uchar_t *iv, size_t ivSize, uchar_t *key, uchar_t *result, size_t resultSize)
{
    Rc4 rc4(iv, ivSize, 3);
    
    size_t i;                      /* result array index */
    uint_t *state = rc4.GetData(); /* S, formula 26, kleins_and_ptw_attacks_on_wep.pdf */
    uchar_t sx;                    /* value of S[idx] */
    uchar_t idx;                   /* index of S, we will find idx by sx */
    uchar_t j3 = rc4.GetY();       /* j3, formula 26, kleins_and_ptw_attacks_on_wep.pdf */
    uchar_t sum = 0;
    
    for (i = 0; i < resultSize; i++) 
    {
        sx = i + ivSize - key[i + ivSize - 1];
        /* Calculate S's index whose value is "i + 3 - X[i + 2]" */
		for(idx = 0; sx != state[idx]; idx++) 
        {}
		sum = sum + state[i + ivSize];
        idx = idx - (j3 + sum);
		result[i] = idx;
	}
}

/**********************class TaskTkipCapturing**********************/
TaskStates TaskTkipCapturing::GetState(const Task *task) const
{
    return TaskStates::TkipCapturing;
}

void TaskTkipCapturing::DoReceive(Task *task, const MacHeader& macHeader)
{
}

CxxEndNameSpace