#include "SystemInclude.h"
#include "SystemError.h" 
#include "Common.h"
#include "Debug.h"

#include "AccessPoint.h"
#include "Option.h"
#include "PtwLib.h"
#include "H802dot11.h"
#include "WepPara.h"
#include "PktDbWrapper.h"
#include "Cracker.h"

#ifdef _DEBUG
#define new DEBUG_CLIENTBLOCK
#endif

using namespace std;
using std::placeholders::_1;
using std::placeholders::_2;
using std::placeholders::_3;

CxxBeginNameSpace(Router)

bool Cracker::IsArpPacket(const DataFrame& dataFrame) const
{
    int size = dataFrame.GetBufSize() - dataFrame.GetMacHeaderSize() - WepPara::GetTotalSize();
    int arpSize = 8 + 8 + 10*2;
        
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
size_t Cracker::CalculateClearStream(uchar_t *buf, size_t bufSize, int *weight, const DataFrame& dataFrame) const
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
        if (dataFrame.GetDestMac().Compare((uchar_t*)"\xff\xff\xff\xff\xff\xff") == 0)
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

Cracker::Cracker(): wrapper(new PcapPktDbWrapper(bind(&Cracker::ReceivePacket, this, _1, _2)))
{    
}

void Cracker::Start() const
{
    wrapper->Start();
}

void Cracker::ReceivePacket(shared_ptr<uchar_t> buf, size_t bufSize)
{
    Option& option = Option::GetInstance();
    shared_ptr<H802dot11> h802dot11(CreateFrame(buf, bufSize));

    /* skip (uninteresting) control frames */
    if (!h802dot11 
        || h802dot11->GetTypeBits() == H802dot11Type::ControlFrameType
        || h802dot11->GetBssid().IsBroadcast())
    {
        return;
    }

    if (option.DoForceBssid() && option.GetBssid() != h802dot11->GetBssid())
    {
        return;
    }

    Aps& aps = Aps::GetInstance();        
    if (aps.Find(h802dot11->GetBssid()) == aps.End())
    {
        Ap ap(h802dot11->GetBssid(), Crypt::Wep);
        aps.Insert(ap);
    }
    Aps::Iterator ap = aps.Find(h802dot11->GetBssid());

    //line 1105, aircrack-ng.c, aircrack-ng-1.2-rc2
    if (option.DoPtw())
    {
        //ap_cur->ptw_clean = ... 
        //ap_cur->ptw_vague = ... 
    }
    St st(h802dot11->GetBssid());
    if (ap->Find(st.GetMac()) == ap->End())
    {
        ap->Insert(st);
    }

    if (h802dot11->GetTypeBits() == H802dot11Type::ManagementFrameType)
    {
        shared_ptr<ManagementFrame> mgmtFrame = dynamic_pointer_cast<ManagementFrame>(h802dot11);
        if (mgmtFrame->GetEssid().size() != 0 && ap->GetEssid().size() == 0)
        {
            ap->SetEssid(mgmtFrame->GetEssid());
        }
    }

    if (h802dot11->GetTypeBits() != H802dot11Type::DataFrameType)
    {
        return; //line 1410, aircrack-ng.c, aircrack-ng-1.2-rc2
    }        

    if (h802dot11->GetMacHeaderSize() + 16 > h802dot11->GetBufSize())
    {
        return;
    }

    DataFrame& dataFrame = *dynamic_pointer_cast<DataFrame>(h802dot11);
    prtstrm << dataFrame << endl;

    //line 1424,  aircrack-ng.c, aircrack-ng-1.2-rc2   ???
    /* frameBody[0] frameBody[1] frameBody[2] are WEP Initialization Vector.
        */
    uchar_t *wepIv = dataFrame.GetFrameBody();
    uchar_t *wepKeyIndex = wepIv + WepPara::GetIvSize();
    if (wepIv[0] != wepIv[1] || wepIv[2] != 0x03)
    {
        ap->SetCrypt(Crypt::Wep);

        if ((wepKeyIndex[0] & 0x20) != 0)
        {
            ap->SetCrypt(Crypt::Wpa);
        }
    }

    /* check the WEP key index. Data Frame, WEP Parameter */
    /* do nothing. */

    if (option.DoPtw())
    {
        uchar_t clear[512] = {0};
        int     weight[16];

        /* frameBody[1] bit0 is ToDs, bit1 is FromDs, 
            means h802dot11->GetToDsBit() == 1 && h802dot11->GetFromDsBit() == 1
        if((frameBody[1] & 0x03) == 0x03) //30 byte header
        {
            body += 6;
            dataSize -=6;
        }
        */

        memset(weight, 0, sizeof(weight));
		memset(clear, 0, sizeof(clear));

        size_t i, clearSize; 
        clearSize = CalculateClearStream(clear, sizeof(clear), weight, dataFrame);
        for (i = 0; i < clearSize; i++)
        {
            clear[i] ^= wepIv[WepPara::GetIvKeyIndexSize() + i];
        }

        if(clearSize != 0)
        {
         //   int i,j;
         //   int il, ir;

         //   i = (iv[0] << 16) | (iv[1] << 8) | (iv[2]);
	        //il = i/8;
	        //ir = 1 << (i%8);

        //    if (PTW_addsession(nullptr, frameBody, clear, weight, k))
        //        ap_cur->nb_ivs_clean++;
        }

        //if (PTW_addsession(nullptr, frameBody, clear, weight, k))
        //{
        //    ap_cur->nb_ivs_vague++;
        //}
    }
    cout << endl;
}

CxxEndNameSpace