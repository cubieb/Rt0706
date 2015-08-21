#include "SystemInclude.h"
#include "Common.h"

#include "Types.h"
#include "MacHeader.h"
#include "SecurityHeader.h"
#include "PtwLib.h"
#include "Rc4.h"
#include "Task.h"
#include "StateMachine.h"

using namespace std;
CxxBeginNameSpace(Router)

/**********************class TaskState**********************/
shared_ptr<TaskState> TaskState::Receive(const MacHeader& macHeader)
{
    if (macHeader.GetTypeBits() == H802dot11Type::ControlFrameType
        || macHeader.GetBssid().IsBroadcast())
    {
        return nullptr;
    }

    return DoReceive(macHeader);
}

/**********************class TaskInit**********************/
TaskStateEnum TaskInit::GetState() const
{
    return TaskStateEnum::Init;
}

shared_ptr<TaskState> TaskInit::DoReceive(const MacHeader& macHeader)
{
    /* do nothing, except change state to TaskCapturing */
    return dynamic_pointer_cast<TaskState>(make_shared<TaskCapturing>(task));
}

/**********************class TaskCapturing**********************/
TaskStateEnum TaskCapturing::GetState() const
{
    return TaskStateEnum::WepCapturing;
}

shared_ptr<TaskState> TaskCapturing::DoReceive(const MacHeader& macHeader)
{
    if (macHeader.GetWepBit() == 0)
    {
        return nullptr; //line 1410, aircrack-ng.c, aircrack-ng-1.2-rc2
    }

    shared_ptr<MacPdu> macPdu(CreateMacPduHeader(macHeader));
    if (macPdu->GetCryptMode() == CryptMode::Wep)
    {
        return dynamic_pointer_cast<TaskState>(make_shared<TaskWepCapturing>(task, macPdu));
    }

    return dynamic_pointer_cast<TaskState>(make_shared<TaskTkipCapturing>(task));
}

/**********************class TaskWepCapturing**********************/
TaskWepCapturing::TaskWepCapturing(std::shared_ptr<Task>& task, const shared_ptr<MacPdu>& theMacPdu)
    : TaskState(task), ptwTable(WepMaxKeySize), macPdu(theMacPdu)
{
    size_t i, j;
    for (i = 0; i < WepMaxKeySize; ++i)
    {
        for (j = 0; j < 256; ++j)
        {
            ptwTable[i][j] = 0;
        }
    }

    pktNumber = 0;
}

TaskStateEnum TaskWepCapturing::GetState() const
{
    return TaskStateEnum::WepCapturing;
}

shared_ptr<TaskState> TaskWepCapturing::DoReceive(const MacHeader& macHeader)
{
    if (macHeader.GetTypeBits() != DataFrameType)
        return nullptr;

    /* line 1424, if( h80211[z] != h80211[z + 1] || h80211[z + 2] != 0x03 ),
       aircrack-ng.c, aircrack-ng-1.2-rc2
       p = dataFrame.GetFrameBody()
       if (p[0] = 0xaa, p[1] = 0xaa, p[2] = 0x03) => logical link control header, 
           so there is not a wep parameter.
       else there must be a wep parameter flowing the 802.11 mac header.
    */
    uchar_t *wepIv = macHeader.GetFrameBodyPtr();

    /* check the WEP key index. Data Frame, WEP Parameter */
    /* do nothing. */
    uchar_t clear[64] = {0};

    size_t i, clearSize; 
    clearSize = CalculateClearStream(clear, sizeof(clear), macHeader);

    uchar_t *snapHeader = wepIv + macPdu->GetHeaderSize();
    for (i = 0; i < clearSize; i++)
    {
        /* calculate KSA of round i+3 */
        clear[i] = clear[i] ^ snapHeader[i];
    }

    /* Start PSW process. */
    uint_t ivId;
    ivId = (wepIv[0] << 16) | (wepIv[1] << 8) | (wepIv[2]);
    if (IvBits.test(ivId))
        return nullptr;
    
    IvBits.set(ivId);
    pktNumber++;

    size_t keySize = ptwTable.GetKeySize();
    shared_ptr<uchar_t> result(new uchar_t[keySize]);
    GuessKeyBytes(wepIv, macPdu->GetIvSize(), clear, result.get(), keySize);
    for (i = 0; i < ptwTable.GetKeySize(); ++i)
    {
        ptwTable[i][result.get()[i]]++;
    }

    if ((pktNumber % 5000) == 10000)
    {
        Check();
    }

    return nullptr;
}

bool TaskWepCapturing::IsArpPacket(const MacHeader& dataFrame) const
{
    int size = macPdu->GetLayer3DataSize(dataFrame);

    /* 1 arp is kind of IP packet, IP packet's min size is 46 byte, 
         so there are 18 bytes padding, lets arp packets up to 46 bytes.
       2 arp 28 bytes + padding 18 bytes + llc 8 bytes = 54 bytes 
     */
    return (size == 54);
}

/* weight is used for guesswork in PTW.  Can be null if known_clear is not for
 * PTW, but just for getting known clear-text.
 */
size_t TaskWepCapturing::CalculateClearStream(uchar_t *buf, size_t bufSize, const MacHeader& dataFrame) const
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

/* PTW_computeKey */
void TaskWepCapturing::Check()
{
    uchar_t fullKey[WepMaxKeySize] = {0};
    PtwValidateChar& validateChar = PtwValidateChar::GetInstance();

    for (size_t i = 0; i < 5; ++i)
    {
        uint_t votes = 0;
        for (uint_t j = 0; j < N; ++j)
        {
            if (!validateChar[j])
                ptwTable[i][j] = 0;

            if (votes < ptwTable[i][j])
            {
                votes = ptwTable[i][j];
                fullKey[i + 3] = (uchar_t)j;
            }
        }
    }

    if (IsCorrect(fullKey))
    {
        cout << "OK" << endl;
    }
}

bool TaskWepCapturing::IsCorrect(uchar_t *fullKey)
{
    return false;
}

/**********************class TaskTkipCapturing**********************/
TaskStateEnum TaskTkipCapturing::GetState() const
{
    return TaskStateEnum::TkipCapturing;
}

shared_ptr<TaskState> TaskTkipCapturing::DoReceive(const MacHeader& macHeader)
{
    return nullptr;
}
CxxEndNameSpace