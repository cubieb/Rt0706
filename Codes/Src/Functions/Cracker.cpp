#include "SystemInclude.h"
#include "SystemError.h" 
#include "Common.h"
#include "Debug.h"

#include "AccessPoint.h"
#include "Option.h"
#include "PtwLib.h"
#include "Pcap.h"
#include "PktDbWrapper.h"
#include "Cracker.h"

#ifdef _DEBUG
#define new DEBUG_CLIENTBLOCK
#endif

using namespace std;
CxxBeginNameSpace(Router)

Cracker::Cracker(): wrapper(new PcapPktDbWrapper<H802dot11>(bind(&Cracker::ReceivePacket, this, placeholders::_1)))
{    
}

void Cracker::Start()
{
    wrapper->Start();
}

void Cracker::ReceivePacket(H802dot11* pkt)
{
    Option& option = Option::GetInstance();
    shared_ptr<H802dot11> h802dot11(pkt);

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