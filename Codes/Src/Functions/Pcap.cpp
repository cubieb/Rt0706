#include "SystemInclude.h"
#include "SystemError.h"
#include "Common.h"
#include "Pcap.h"

CxxBeginNameSpace(Router)
using namespace std;

PcapFile::PcapFile(const char *fileName)
{
    fstream pcapFile(fileName, ios_base::in  | ios::binary);
    
    if (pcapFile == nullptr)
    {
        throw system_error(system_error_t::file_not_exists);
    }
    streampos start = pcapFile.tellg();
    pcapFile.read(reinterpret_cast<char *>(&magic), sizeof(magic));
    pcapFile.read(reinterpret_cast<char *>(&versionMajor), sizeof(versionMajor));
    pcapFile.read(reinterpret_cast<char *>(&versionMinor), sizeof(versionMinor));
    pcapFile.read(reinterpret_cast<char *>(&reserved1), sizeof(reserved1));
    pcapFile.read(reinterpret_cast<char *>(&reserved2), sizeof(reserved2));
    pcapFile.read(reinterpret_cast<char *>(&reserved3), sizeof(reserved3));
    pcapFile.read(reinterpret_cast<char *>(&linkType), sizeof(linkType));

    if (magic != TcpDumpMagic)
    {
        throw system_error(system_error_t::bad_file_type);
    }

    /* calculate file size */
    pcapFile.seekg(0, ios::end);      
    streampos end = pcapFile.tellg();
    fileSize = static_cast<size_t>(end - start); 
}

size_t PcapFile::GetHeaderSize()
{
    /* return sizeof(magic) + sizeof(versionMajor) + sizeof(versionMinor) 
                     + sizeof(reserved1)+ sizeof(reserved2) + sizeof(reserved3)
                     + sizeof(linkType); */
    return 24; 
}

size_t PcapFile::GetFileSize()
{
    return fileSize; 
}

PcapPacketHeader::PcapPacketHeader(const char *fileName, size_t offset)
{
    fstream pcapFile(fileName, ios_base::in  | ios::binary);
    if (pcapFile == nullptr)
    {
        throw system_error(system_error_t::file_not_exists);
    }
    pcapFile.seekp(offset);
    pcapFile.read(reinterpret_cast<char *>(&ts), sizeof(ts));
    pcapFile.read(reinterpret_cast<char *>(&caplen), sizeof(caplen));
    pcapFile.read(reinterpret_cast<char *>(&len), sizeof(len));
}

size_t PcapPacketHeader::GetSize()
{
    return sizeof(struct timeval) + sizeof(uint32_t) + sizeof(uint32_t);
}

/*******************************/
H802dot11::H802dot11(const shared_ptr<uchar_t>& theBuf, size_t theBufSize)
    : buf(theBuf), bufSize(theBufSize)
{}

H802dot11::~H802dot11() 
{}

size_t H802dot11::GetBufSize() const
{
    return bufSize;
}

uchar_t H802dot11::GetProtocolBits() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = ptr[FrameControl] & 0x3;
    return value;
}

uchar_t H802dot11::GetTypeBits() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = (ptr[FrameControl] >> 2) & 0x3;
    return value;
}

uchar_t H802dot11::GetSubtypeBits() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = (ptr[FrameControl] >> 4) & 0xF;
    return value;
}

uchar_t H802dot11::GetToDsBit() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = ptr[FrameControl + 1] & 0x1;
    return value;
}

uchar_t H802dot11::GetFromDsBit() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = (ptr[FrameControl + 1] >> 1) & 0x1;
    return value;
}

uchar_t H802dot11::GetMoreTagBit() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = (ptr[FrameControl + 1] >> 2) & 0x1;
    return value;
}

uchar_t H802dot11::GetRetryBit() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = (ptr[FrameControl + 1] >> 3) & 0x1;
    return value;
}

uchar_t H802dot11::GetPowerMgmtBit() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = (ptr[FrameControl + 1] >> 4) & 0x1;
    return value;
}

uchar_t H802dot11::GetMoreDataBit() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = (ptr[FrameControl + 1] >> 5) & 0x1;
    return value;
}

uchar_t H802dot11::GetWepBit() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = (ptr[FrameControl + 1] >> 6) & 0x1;
    return value;
}

uchar_t* H802dot11::GetFramePtr() const
{
    return buf.get();
}

uchar_t* H802dot11::GetFrameBody() const
{
    return buf.get() + GetMacHeaderSize();
}

void H802dot11::Put(std::ostream& os) const
{
    os << endl << MemStream<uchar_t>(buf.get(), 32) << endl;

    os << "version = " << (uint_t) GetProtocolBits()
       << ", type = " << (uint_t) GetTypeBits()
       << ", subtype = " << (uint_t) GetSubtypeBits()
       << ", ToDs = " << (uint_t) GetToDsBit()
       << ", FromDs = " << (uint_t) GetFromDsBit() 
       << ", Wep = " << (uint_t) GetWepBit();
}

/******************************/
ManagementFrame::ManagementFrame(const shared_ptr<uchar_t>& buf, size_t bufSize)
    : H802dot11(buf, bufSize)
{
}

ManagementFrame::~ManagementFrame()
{}

Mac ManagementFrame::GetDestMac() const
{
    return Mac(buf.get() + Addr1);
}

Mac ManagementFrame::GetBssid() const
{
    return Mac(buf.get() + Addr3);
}

string ManagementFrame::GetEssid() const
{
    uchar_t* ptr;
    string essid;
    for (ptr = buf.get() + GetMacHeaderSize() + GetFixedParaSize(); 
         ptr < buf.get() + bufSize; 
         ptr = ptr + 2 + ptr[1])
    {
        if (ptr[0] == 0)
        {
            if (ptr[1] > 0 && ptr[2] != '\0')
            {
                essid.append(reinterpret_cast<char*>(ptr + 2), ptr[1]);
            }
            break;
        }
    }

    return essid;
}

void ManagementFrame::Put(ostream& os) const
{
    H802dot11::Put(os);

    os << "Da = " << GetDestMac()
        << ", Bssid = " << GetBssid()
        << ", Essid = " << GetEssid();
}

/*******************************/
AssociationRequestFrame::AssociationRequestFrame(const shared_ptr<uchar_t>& buf, size_t bufSize)
    : ManagementFrame(buf, bufSize)
{}

AssociationRequestFrame::~AssociationRequestFrame()
{}

size_t AssociationRequestFrame::GetMacHeaderSize() const
{
    return AssociationRequestMacHeaderSize;
}

size_t AssociationRequestFrame::GetFixedParaSize() const
{
    return AssociationRequestFixedFieldSize;
}

uint16_t AssociationRequestFrame::GetListenInterval() const
{
    uint16_t value;
    Read16(buf.get() + GetMacHeaderSize() + ListenInterval, value);
    return value;
}

void AssociationRequestFrame::Put(std::ostream& os) const
{
    ManagementFrame::Put(os);
    os << ", ListenInterval = " << (uint_t)GetListenInterval();
}

/*******************************/
BeaconFrame::BeaconFrame(const shared_ptr<uchar_t>& buf, size_t bufSize)
    : ManagementFrame(buf, bufSize)
{}

BeaconFrame::~BeaconFrame()
{}

size_t BeaconFrame::GetMacHeaderSize() const
{
    return BeaconMacHeaderSize;
}

size_t BeaconFrame::GetFixedParaSize() const
{
    return BeaconFixedFieldSize;
}

uchar_t* BeaconFrame::GetTimeStamp()
{
    return buf.get() + GetMacHeaderSize() + TimeStamp;
}

uint16_t BeaconFrame::GetBeaconInterval() const
{
    uint16_t value;
    Read16(buf.get() + GetMacHeaderSize() + BeaconInterval, value);
    return value;
}

uchar_t BeaconFrame::GetEssOfCapabilityBit() const
{
    uchar_t* ptr = buf.get() + GetMacHeaderSize();
    uchar_t value = ptr[CapabilityInfo] & 0x1;
    return value;
}

uchar_t BeaconFrame::GetIbssStatusOfCapabilityBit() const
{
    uchar_t* ptr = buf.get() + GetMacHeaderSize();
    uchar_t value = (ptr[CapabilityInfo] >> 1) & 0x1;
    return value;
}

uchar_t BeaconFrame::GetPrivacyOfCapabilityBit() const
{
    uchar_t* ptr = buf.get() + GetMacHeaderSize();
    uchar_t value = (ptr[CapabilityInfo] >> 4) & 0x1;
    return value;
}

void BeaconFrame::Put(std::ostream& os) const
{
    ManagementFrame::Put(os);
    os << ", ESS bit = " << (uint_t)GetEssOfCapabilityBit()
        << ", IBSS status bit = " << (uint_t)GetIbssStatusOfCapabilityBit();
}

/*******************************/
ProbeResponseFrame::ProbeResponseFrame(const shared_ptr<uchar_t>& buf, size_t bufSize)
    : ManagementFrame(buf, bufSize)
{}

ProbeResponseFrame::~ProbeResponseFrame()
{}

size_t ProbeResponseFrame::GetMacHeaderSize() const
{
    return ProbeResponseMacHeaderSize;
}

size_t ProbeResponseFrame::GetFixedParaSize() const
{
    return ProbeResponseFixedFieldSize;
}

uchar_t* ProbeResponseFrame::GetTimeStamp()
{
    return buf.get() + GetMacHeaderSize() + BeaconFrame::TimeStamp;
}

uint16_t ProbeResponseFrame::GetBetweenInterval() const
{
    uint16_t value;
    Read16(buf.get() + GetMacHeaderSize() + BetweenInterval, value);
    return value;
}

uchar_t ProbeResponseFrame::GetEssCapabilityBit() const
{
    uchar_t* ptr = buf.get() + GetMacHeaderSize();
    uchar_t value = ptr[CapabilityInfo] & 0x1;
    return value;
}

uchar_t ProbeResponseFrame::GetIbssStatusBit() const
{
    uchar_t* ptr = buf.get() + GetMacHeaderSize();
    uchar_t value = (ptr[CapabilityInfo] >> 1) & 0x1;
    return value;
}

uchar_t ProbeResponseFrame::GetPrivacyBit() const
{
    uchar_t* ptr = buf.get() + GetMacHeaderSize();
    uchar_t value = (ptr[CapabilityInfo] >> 4) & 0x1;
    return value;
}

void ProbeResponseFrame::Put(std::ostream& os) const
{
    ManagementFrame::Put(os);
    os << ", ESS bit = " << (uint_t)GetEssCapabilityBit()
        << ", IBSS status bit = " << (uint_t)GetIbssStatusBit();
}

/*******************************/
ProbeRequestFrame::ProbeRequestFrame(const shared_ptr<uchar_t>& buf, size_t bufSize)
    : ManagementFrame(buf, bufSize)
{}

ProbeRequestFrame::~ProbeRequestFrame()
{}

size_t ProbeRequestFrame::GetMacHeaderSize() const
{
    return ProbeRequestMacHeaderSize;
}

size_t ProbeRequestFrame::GetFixedParaSize() const
{
    return ProbeRequestFixedFieldSize;
}

/*******************************/
DataFrame::DataFrame(const shared_ptr<uchar_t>& buf, size_t bufSize)
    : H802dot11(buf, bufSize)
{}

DataFrame::~DataFrame()
{}

Mac DataFrame::GetDestMac() const
{
    static uchar_t offset[2][2] =
    {
        {Addr1, Addr1},
        {Addr3, Addr3}
    };
    uchar_t toDs = GetToDsBit();
    uchar_t fromDs = GetFromDsBit();
    return Mac(buf.get() + offset[toDs][fromDs]);
}

Mac DataFrame::GetSrcMac() const
{
    static uchar_t offset[2][2] =
    {
        {Addr2, Addr3},
        {Addr2, Addr4}
    };
    
    uchar_t toDs = GetToDsBit();
    uchar_t fromDs = GetFromDsBit();

    return Mac(buf.get() + offset[toDs][fromDs]);
}

Mac DataFrame::GetBssid() const
{
    static uchar_t offset[2][2] =
    {
        {Addr3, Addr2},
        {Addr1, 0}
    };
    
    uchar_t toDs = GetToDsBit();
    uchar_t fromDs = GetFromDsBit();
    assert(toDs != 1 || fromDs != 1);

    return Mac(buf.get() + offset[toDs][fromDs]);
}

size_t DataFrame::GetMacHeaderSize() const
{
    if ((GetSubtypeBits() & 0x08) != 0)
    {
        if (GetToDsBit() == 1 && GetFromDsBit() == 1)
            return DataMacHeaderSize11 + 2;

        return DataMacHeaderSizeXx + 2;
    }

    if (GetToDsBit() == 1 && GetFromDsBit() == 1)
        return DataMacHeaderSize11;

    return DataMacHeaderSizeXx;
}

void DataFrame::Put(std::ostream& os) const
{
    H802dot11::Put(os);
}

H802dot11* CreateFrame(const std::shared_ptr<uchar_t>& buf, size_t bufSize)
{
    uchar_t *ptr = buf.get();
    uchar_t type = (ptr[FrameControl] >> 2) & 0x3;
    uchar_t subType = (ptr[FrameControl] >> 4) & 0xF;

    H802dot11 *h802dot11 = nullptr;
    switch (type)
    {
    case ManagementFrameType:
        switch (subType)
        {
        case AssociationRequest:
            h802dot11 = new AssociationRequestFrame(buf, bufSize);
            break;
            
        case Beacon:
            h802dot11 = new BeaconFrame(buf, bufSize);
            break;

        case ProbeResponse:
            h802dot11 = new ProbeResponseFrame(buf, bufSize);
            break;

        case ProbeRequest:
            h802dot11 = new ProbeRequestFrame(buf, bufSize);
            break;
        }
        break;

    case DataFrameType:
        h802dot11 = new DataFrame(buf, bufSize);
        break;

    default:
        break;
    }

    return h802dot11;
}

CxxEndNameSpace

