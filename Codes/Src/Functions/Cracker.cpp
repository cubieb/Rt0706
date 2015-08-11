#include "SystemInclude.h"
#include "SystemError.h" 
#include "Common.h"
#include "Debug.h"

#include "Option.h"
#include "MacHeader.h"
#include "SecurityHeader.h"
#include "PtwLib.h"
#include "PktDbWrapper.h"
#include "Rc4.h"
#include "Task.h"
#include "Cracker.h"

#ifdef _DEBUG
#define new DEBUG_CLIENTBLOCK
#endif

using namespace std;
using std::placeholders::_1;
using std::placeholders::_2;
using std::placeholders::_3;

CxxBeginNameSpace(Router)

Cracker::Cracker()
    : wrapper(new PcapPktDbWrapper(bind(&Cracker::ReceivePacket, this, _1, _2)))
{
}

void Cracker::Start() const
{
    wrapper->Start();
}

void Cracker::ReceivePacket(shared_ptr<uchar_t> buf, size_t bufSize)
{
    Option& option = Option::GetInstance();
    shared_ptr<MacHeader> macHeader(CreateMacHeader(buf, bufSize));

    /* skip unknown Mac Frame type */
    if (macHeader  == nullptr)
    {
        return;
    }

    Tasks& tasks = Tasks::GetInstance();
    Tasks::Iterator iter = tasks.Find(macHeader->GetBssid());
    if (iter == tasks.End())
    {
        shared_ptr<Task> task(new Task(macHeader->GetBssid(), GetMyMac(), bind(&Cracker::StateChanged, this, _1)));
        std::pair<Tasks::Iterator, bool> ret = tasks.Insert(task);
        if (!ret.second)
        {
            return;
        }
        iter = ret.first;
    }
    (*iter)->Receive(*macHeader);    
}

void Cracker::StateChanged(Task& task)
{
}

CxxEndNameSpace