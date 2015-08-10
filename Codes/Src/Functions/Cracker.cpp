#include "SystemInclude.h"
#include "SystemError.h" 
#include "Common.h"
#include "Debug.h"

#include "AccessPoint.h"
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

bool Cracker::IsArpPacket(const MacHeader& dataFrame) const
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
size_t Cracker::CalculateClearStream(uchar_t *buf, size_t bufSize, int *weight, const MacHeader& dataFrame) const
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

Cracker::Cracker()
    : wrapper(new PcapPktDbWrapper(bind(&Cracker::ReceivePacket, this, _1, _2))),
      state(new PswState)
{    
    size_t i, j;
    for (i = 0; i < WepMaxKeySize; ++i)
        for (j = 0; j < 256; ++j)
            state->table[i][j] = 0;
}

void Cracker::Start() const
{
    wrapper->Start();
}

void Cracker::ReceivePacket(shared_ptr<uchar_t> buf, size_t bufSize)
{
    Option& option = Option::GetInstance();
    shared_ptr<MacHeader> macHeader(CreateMacHeader(buf, bufSize));

    /* skip (uninteresting) control frames */
    if (macHeader  == nullptr
        || macHeader->GetTypeBits() == H802dot11Type::ControlFrameType
        || macHeader->GetBssid().IsBroadcast())
    {
        return;
    }

    Tasks& tasks = Tasks::GetInstance();
    Tasks::Iterator iter = tasks.Find(macHeader->GetBssid());
    if (iter == tasks.End())
    {
        shared_ptr<Task> task(new Task(macHeader->GetBssid(), GetMyRouterId(), bind(&Cracker::StateChanged, this, _1)));
        std::pair<Tasks::Iterator, bool> ret = tasks.Insert(task);
        if (!ret.second)
        {
            return;
        }
        iter = ret.first;
    }
    (*iter)->Receive(*macHeader);    
    

    if (option.DoForceBssid() && option.GetBssid() != macHeader->GetBssid())
    {
        return;
    }
    
    Aps& aps = Aps::GetInstance();        
    if (aps.Find(macHeader->GetBssid()) == aps.End())
    {
        Ap ap(macHeader->GetBssid(), CryptMode::Wep);
        aps.Insert(ap);
    }
    Aps::Iterator ap = aps.Find(macHeader->GetBssid());

    //line 1105, aircrack-ng.c, aircrack-ng-1.2-rc2
    if (option.DoPtw())
    {
        //ap_cur->ptw_clean = ... 
        //ap_cur->ptw_vague = ... 
    }
    St st(macHeader->GetBssid());
    if (ap->Find(st.GetMac()) == ap->End())
    {
        ap->Insert(st);
    }

    if (macHeader->GetTypeBits() == H802dot11Type::ManagementFrameType)
    {
        shared_ptr<ManagementFrame> mgmtFrame = dynamic_pointer_cast<ManagementFrame>(macHeader);
        if (mgmtFrame->GetEssid().size() != 0 && ap->GetEssid().size() == 0)
        {
            ap->SetEssid(mgmtFrame->GetEssid());
        }
    }

    if (macHeader->GetTypeBits() != H802dot11Type::DataFrameType
        || macHeader->GetFrameBodySize() <= 16
        || macHeader->GetWepBit() == 0)
    {
        return; //line 1410, aircrack-ng.c, aircrack-ng-1.2-rc2
    }        

    /* line 1424, if( h80211[z] != h80211[z + 1] || h80211[z + 2] != 0x03 ),
       aircrack-ng.c, aircrack-ng-1.2-rc2
       p = dataFrame.GetFrameBody()
       if (p[0] = 0xaa, p[1] = 0xaa, p[2] = 0x03) => logical link control header, so there is not a wep parameter.
       else there must be a wep parameter flowing the 802.11 mac header.
     */
    uchar_t *wepIv = macHeader->GetFrameBodyPtr();
    shared_ptr<SecurityHeader> protectedMpdu(CreateSecurityHeader(*macHeader));
    ap->SetCrypt(protectedMpdu->GetCryptMode());

    /* check the WEP key index. Data Frame, WEP Parameter */
    /* do nothing. */
    uchar_t clear[512] = {0};
    int     weight[16];

    memset(weight, 0, sizeof(weight));
	memset(clear, 0, sizeof(clear));

    size_t i, clearSize; 
    clearSize = CalculateClearStream(clear, sizeof(clear), weight, *macHeader);
    uchar_t *snapHeader = wepIv + protectedMpdu->GetHeaderSize();
    for (i = 0; i < clearSize; i++)
    {
        /* calculate KSA of round i+3 */
        clear[i] = clear[i] ^ snapHeader[i];
    }
    /* Start PSW process. */
    uint_t ivId;
    ivId = (wepIv[0] << 16) | (wepIv[1] << 8) | (wepIv[2]);
    if (state->IvBits.test(ivId))
        return;

    state->IvBits.set(ivId);
    uint8_t result[WepMaxKeySize];
    GuessKeyBytes(wepIv, protectedMpdu->GetIvSize(), clear, result, WepMaxKeySize);
    for (i = 0; i < WepMaxKeySize; ++i)
    {
        state->table[i][result[i]]++;
    }
}

void Cracker::StateChanged(Task& task)
{
}
/*
 */

/*
Parameter:
    key: the X of formula 26. "kleins_and_ptw_attacks_on_wep.pdf"
*/
void Cracker::GuessKeyBytes(uchar_t *iv, size_t ivSize, uchar_t *key, uchar_t *result, size_t resultSize)
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

CxxEndNameSpace