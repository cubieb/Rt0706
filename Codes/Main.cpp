/*  history:
2015-07-06 Created by LiuHao.
*/

#include "SystemInclude.h"
#include "Common.h"
#include "Rc4.h"
#include "Pcap.h"
#include "Debug.h"
#include "AccessPoint.h"
#include "Option.h"
#include "SystemError.h" 

#include "Main.h"

using namespace std;
using namespace Router;

const char* PcapFileName = "../Packets/aircrack-ng-ptw.cap";
//const char* PcapFileName = "../Packets/handshake.cap";

void Crack()
{
    Option& option = Option::GetInstance();

    PcapFile pcapFile(PcapFileName);
    if (pcapFile.linkType != LinkType::ieee802dot11)
    {
        cerr << "bad file type." << endl;
    }

    size_t offset = pcapFile.GetHeaderSize();
    while (offset < pcapFile.GetFileSize())
    {
        PcapPacketHeader pcapPacketHeader(PcapFileName, offset);
        size_t packetOff = offset + pcapPacketHeader.GetSize();
        offset = offset + pcapPacketHeader.caplen + pcapPacketHeader.GetSize();

        if (pcapPacketHeader.caplen < 24)
        {
            continue;
        }
        
        H802dot11 h802dot11(PcapFileName, packetOff, pcapPacketHeader.caplen);
        /* skip (uninteresting) control frames */
        if (h802dot11.GetType() == H802dot11Type::ControlFrameType)
        {
            continue;
        }

        if (h802dot11.GetBssid().IsBroadcast())
        {
            /* probe request or such - skip the packet */
            continue;
        }

        if (option.DoForceBssid() && option.GetBssid() != h802dot11.GetBssid())
        {
            continue;
        }

        Aps& aps = Aps::GetInstance();        
        if (aps.Find(h802dot11.GetBssid()) == aps.End())
        {
            Ap ap(h802dot11.GetBssid(), Crypt::Wep);
            aps.Insert(ap);
        }
        Aps::Iterator ap = aps.Find(h802dot11.GetBssid());

        if (option.DoPtw())
        {
            //ap_cur->ptw_clean = ... 
            //ap_cur->ptw_vague = ... 
        }
        St st(h802dot11.GetBssid());
        if (ap->Find(st.GetMac()) == ap->End())
        {
            ap->Insert(st);
        }

        uchar_t subType;
        switch (h802dot11.GetType())
        {
        case (H802dot11Type::ManagementFrameType):        
            /* packet parsing: Beacon or Probe Response */  
            /* packet parsing: Association Request <==> aircrack-ng-1.2-rc2, aircrack-ng.c, line 1377, */
            subType = h802dot11.GetSubtype();
            if (subType == H802dot11Subtype::Beacon)
            {
                BeaconFrame beacon(h802dot11);
                if (beacon.GetEssid().length() != 0 && ap->GetEssid().length() == 0)
                {
                    ap->SetEssid(beacon.GetEssid());
                }
                prtstrm << beacon << endl;
            }
            else if (subType == H802dot11Subtype::ProbeResponse ||
                subType == H802dot11Subtype::AssociationRequest)
            {
                //ManagementFrame& mngHeader = h802dot11.GetManagementFrame();
                //if (mngHeader.GetEssid().length() != 0 && ap->GetEssid().length() == 0)
                //{
                //    ap->SetEssid(mngHeader.GetEssid());
                //}
                //dbgstrm << mngHeader << endl;
            }
            break;

        case (H802dot11Type::DataFrameType):
            {
                //DataFrame& dataFrame = h802dot11.GetDataFrame();
            }
            break;
        }

        prtstrm << h802dot11 << endl;
    }
}

int main()
{
    Crack();

    system("Pause");
	return 0;
}
