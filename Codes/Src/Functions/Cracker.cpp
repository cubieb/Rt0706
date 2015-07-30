#include "SystemInclude.h"
#include "SystemError.h" 
#include "Common.h"
#include "Debug.h"

#include "AccessPoint.h"
#include "Option.h"
#include "PtwLib.h"
#include "H802dot11.h"
#include "PktDbWrapper.h"
#include "Cracker.h"

#ifdef _DEBUG
#define new DEBUG_CLIENTBLOCK
#endif

using namespace std;
CxxBeginNameSpace(Router)

bool IsArpPacket(DataFrame& dataFrame)
{
    int size = dataFrame.GetBufSize() - dataFrame.GetMacHeaderSize() - dataFrame.GetWepParaTotalSize();
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
int known_clear(void *clear, int *clen, int *weight, DataFrame& dataFrame)
{
    size_t len;
    uchar_t *ptr = (uchar_t*)clear;
    int num = 1;

    if(IsArpPacket(dataFrame)) /*arp*/
    {
        len = LlcSnap::GetSize();
        memcpy(ptr, LlcSnap::GetLlcSnapArp(), len);
        ptr += len;

        /* arp header */
        len = 6;
        memcpy(ptr, "\x00\x01\x08\x00\x06\x04", len);
        ptr += len;

        /* type of arp */
        len = 2;
        if (dataFrame.GetDestMac().Compare((uchar_t*)"\xff\xff\xff\xff\xff\xff") == 0)
            memcpy(ptr, "\x00\x01", len);
        else
            memcpy(ptr, "\x00\x02", len);
        ptr += len;

        /* src mac */
        len = 6;
        memcpy(ptr, dataFrame.GetSrcMac().GetPtr(), len);
        ptr += len;

        len = ptr - ((uchar_t*)clear);
        *clen = len;
        if (weight)
            weight[0] = 256;
        return 1;
    }

    return 1;
}

Cracker::Cracker(): wrapper(new PcapPktDbWrapper(bind(&Cracker::ReceivePacket, this, placeholders::_1, placeholders::_2)))
{    
}

void Cracker::Start()
{
    wrapper->Start();
}

void Cracker::ReceivePacket(shared_ptr<uchar_t> buf, size_t bufSize)
{
    Option& option = Option::GetInstance();
    shared_ptr<H802dot11> h802dot11(CreateFrame(buf, bufSize));

    /* skip (uninteresting) control frames */
    if (!h802dot11 || h802dot11->GetTypeBits() == H802dot11Type::ControlFrameType)
    {
        return;
    }

    if (h802dot11->GetBssid().IsBroadcast())
    {
        /* probe request or such - skip the packet */
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
    uchar_t *wepIv = dataFrame.GetWepIvPtr();
    uchar_t *wepKeyIndex = dataFrame.GetWepKeyIndexPtr();
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
        uchar_t *body = dataFrame.GetFrameBody();
        size_t dataSize = dataFrame.GetBufSize() 
                            - dataFrame.GetMacHeaderSize() 
                            - dataFrame.GetWepParaTotalSize(); 

        uchar_t clear[2048];
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

        //int clearSize, i, j, k; 
        //k = known_clear(clear, &clearSize, weight, dataFrame);
        //for (j=0; j<k; j++)
        //{
        //    for (i = 0; i < clearSize; i++)
        //        clear[i+(32*j)] ^= body[4+i];
        //}

        //if(k==1)
        //{
        //    if (PTW_addsession(nullptr, body, clear, weight, k))
        //        ap_cur->nb_ivs_clean++;
        //}

        //if (PTW_addsession(nullptr, body, clear, weight, k))
        //{
        //    ap_cur->nb_ivs_vague++;
        //}
    }
    cout << endl;
}

CxxEndNameSpace