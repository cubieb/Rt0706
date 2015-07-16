#include "SystemInclude.h"
#include "SystemError.h"
#include "Common.h"
#include "Pcap.h"

CxxBeginNameSpace(Router)
using namespace std;

PcapFileHeader::PcapFileHeader(const char *fileName)
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

size_t PcapFileHeader::GetHeaderSize()
{
    /* return sizeof(magic) + sizeof(versionMajor) + sizeof(versionMinor) 
                     + sizeof(reserved1)+ sizeof(reserved2) + sizeof(reserved3)
                     + sizeof(linkType); */
    return 24; 
}

size_t PcapFileHeader::GetFileSize()
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

/******************************/
ManagementFrame::ManagementFrame(shared_ptr<uchar_t> theBuff, size_t theOffset, size_t theFrameSize)
    : buf(theBuff), offset(theOffset), frameSize(theFrameSize)
{}

ManagementFrame::ManagementFrame(const ManagementFrame& right)
    : buf(right.buf), offset(right.offset),frameSize(right.frameSize)
{}

string ManagementFrame::GetEssid() const
{
    uchar_t* ptr;
    string essid;
    for (ptr = buf.get() + offset + GetFixFieldSize(); 
         ptr < buf.get() + offset + GetFixFieldSize() + frameSize; 
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
    os << "Essid = " << GetEssid();
}

ostream& operator << (ostream& os, ManagementFrame const& header)
{
    header.Put(os);
    return os;
}

/*******************************/
AssociationRequestFrame::AssociationRequestFrame(std::shared_ptr<uchar_t> theBuff, 
                                                 size_t theOffset, size_t theFrameSize)
    : ManagementFrame(theBuff, theOffset, theFrameSize), ptr(theBuff.get() + theOffset)
{}

AssociationRequestFrame::AssociationRequestFrame(const AssociationRequestFrame& right) 
    : ManagementFrame(right), ptr(buf.get() + offset)
{}

ManagementFrame* AssociationRequestFrame::CreateInstance(std::shared_ptr<uchar_t> buff, 
        size_t offset, size_t frameSize)
{
    return new AssociationRequestFrame(buff, offset, frameSize);
}

size_t AssociationRequestFrame::GetFixFieldSize() const
{
    return AssociationRequestFixedFieldSize;
}

uint16_t AssociationRequestFrame::GetListenInterval() const
{
    uint16_t value;
    Read16(ptr + ListenInterval, value);
    return value;
}

void AssociationRequestFrame::Put(std::ostream& os) const
{
    ManagementFrame::Put(os);
    os << ", ListenInterval = " << (uint_t)GetListenInterval();
}

/*******************************/
BeaconFrame::BeaconFrame(std::shared_ptr<uchar_t> theBuff, 
                         size_t theOffset, size_t theFrameSize)
    : ManagementFrame(theBuff, theOffset, theFrameSize), ptr(theBuff.get() + theOffset)
{}

BeaconFrame::BeaconFrame(const BeaconFrame& right) : ManagementFrame(right), ptr(buf.get() + offset)
{}

ManagementFrame* BeaconFrame::CreateInstance(std::shared_ptr<uchar_t> buff, 
        size_t offset, size_t frameSize)
{
    return new BeaconFrame(buff, offset, frameSize);
}

size_t BeaconFrame::GetFixFieldSize() const
{
    return BeaconFixedFieldSize;
}

uchar_t* BeaconFrame::GetTimeStamp()
{
    return ptr + TimeStamp;
}

uint16_t BeaconFrame::GetBeaconInterval() const
{
    uint16_t value;
    Read16(ptr + BeaconInterval, value);
    return value;
}

uchar_t BeaconFrame::GetEssCapabilityBit() const
{
    uchar_t value = ptr[CapabilityInfo] & 0x1;
    return value;
}

uchar_t BeaconFrame::GetIbssStatusBit() const
{
    uchar_t value = (ptr[CapabilityInfo] >> 1) & 0x1;
    return value;
}

uchar_t BeaconFrame::GetPrivacyBit() const
{
    uchar_t value = (ptr[CapabilityInfo] >> 4) & 0x1;
    return value;
}

void BeaconFrame::Put(std::ostream& os) const
{
    ManagementFrame::Put(os);
    os << ", ESS bit = " << (uint_t)GetEssCapabilityBit()
        << ", IBSS status bit = " << (uint_t)GetIbssStatusBit();
}

/*******************************/
ProbeResponseFrame::ProbeResponseFrame(std::shared_ptr<uchar_t> theBuff, 
                                       size_t theOffset, size_t theFrameSize)
    : ManagementFrame(theBuff, theOffset, theFrameSize), ptr(theBuff.get() + theOffset)
{}

ProbeResponseFrame::ProbeResponseFrame(const ProbeResponseFrame& right)
    : ManagementFrame(right), ptr(buf.get() + offset)
{}

ManagementFrame* ProbeResponseFrame::CreateInstance(std::shared_ptr<uchar_t> buff, 
        size_t offset, size_t frameSize)
{
    return new ProbeResponseFrame(buff, offset, frameSize);
}

size_t ProbeResponseFrame::GetFixFieldSize() const
{
    return ProbeResponseFixedFieldSize;
}

uchar_t* ProbeResponseFrame::GetTimeStamp()
{
    return ptr + BeaconFrame::TimeStamp;
}

uint16_t ProbeResponseFrame::GetBeaconInterval() const
{
    uint16_t value;
    Read16(ptr + BeaconFrame::BeaconInterval, value);
    return value;
}

uchar_t ProbeResponseFrame::GetEssCapabilityBit() const
{
    uchar_t value = ptr[BeaconFrame::CapabilityInfo] & 0x1;
    return value;
}

uchar_t ProbeResponseFrame::GetIbssStatusBit() const
{
    uchar_t value = (ptr[BeaconFrame::CapabilityInfo] >> 1) & 0x1;
    return value;
}

uchar_t ProbeResponseFrame::GetPrivacyBit() const
{
    uchar_t value = (ptr[BeaconFrame::CapabilityInfo] >> 4) & 0x1;
    return value;
}

void ProbeResponseFrame::Put(std::ostream& os) const
{
    ManagementFrame::Put(os);
    os << ", ESS bit = " << (uint_t)GetEssCapabilityBit()
        << ", IBSS status bit = " << (uint_t)GetIbssStatusBit();
}

/*******************************/
ProbeRequestFrame::ProbeRequestFrame(std::shared_ptr<uchar_t> theBuff, 
                                     size_t theOffset, size_t theFrameSize)
    : ManagementFrame(theBuff, theOffset, theFrameSize)
{}

ProbeRequestFrame::ProbeRequestFrame(const ProbeRequestFrame& right)
    : ManagementFrame(right)
{}

ManagementFrame* ProbeRequestFrame::CreateInstance(std::shared_ptr<uchar_t> buff, 
        size_t offset, size_t frameSize)
{
    return new ProbeRequestFrame(buff, offset, frameSize);
}

size_t ProbeRequestFrame::GetFixFieldSize() const
{
    return ProbeRequestFixedFieldSize;
}

/*******************************/
H802dot11::H802dot11(const char *fileName, size_t offset, size_t theFrameSize)
    : buf(new uchar_t[theFrameSize]),
    frameSize(theFrameSize), managementFrame(nullptr)
{
    fstream pcapFile(fileName, ios_base::in | ios::binary);
    if (pcapFile == nullptr)
    {
        throw system_error(system_error_t::file_not_exists);
    }
    pcapFile.seekp(offset);
    pcapFile.read(reinterpret_cast<char*>(buf.get()), frameSize);

    classFactor.insert(make_pair((AssociationRequest << 2) | ManagementFrameType, 
        make_pair(AssociationRequestFrame::CreateInstance, AssociationRequestMacHeaderSize)));
    classFactor.insert(make_pair((Beacon << 2) | ManagementFrameType, 
        make_pair(BeaconFrame::CreateInstance, BeaconMacHeaderSize)));
    classFactor.insert(make_pair((ProbeResponse << 2) | ManagementFrameType, 
        make_pair(ProbeResponseFrame::CreateInstance, ProbeResponseMacHeaderSize)));
    classFactor.insert(make_pair((ProbeRequest << 2) | ManagementFrameType, 
        make_pair(ProbeRequestFrame::CreateInstance, ProbeRequestMacHeaderSize)));
}

H802dot11::~H802dot11() 
{
    if (managementFrame != nullptr)
    {
        delete managementFrame;
    }
}

uchar_t H802dot11::GetVersion() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = ptr[FrameControl] & 0x3;
    return value;
}

uchar_t H802dot11::GetType() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = (ptr[FrameControl] >> 2) & 0x3;
    return value;
}

uchar_t H802dot11::GetSubtype() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = (ptr[FrameControl] >> 4) & 0xF;
    return value;
}

void H802dot11::Put(std::ostream& os) const
{
    os << "version = " << (uint_t) GetVersion()
       << ", type = " << (uint_t) GetType()
       << ", subtype = " << (uint_t) GetSubtype()
       << ", ToDs = " << (uint_t) GetToDs()
       << ", FromDs = " << (uint_t) GetFromDs() << endl;

    os << "bssid  = " << GetBssid() << endl;
    os << "dstMac = " << GetDestMac() << endl;
}

uchar_t H802dot11::GetToDs() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = ptr[FrameControl + 1] & 0x1;
    return value;
}

uchar_t H802dot11::GetFromDs() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = (ptr[FrameControl + 1] >> 1) & 0x1;
    return value;
}

Mac H802dot11::GetBssid() const
{
    static uchar_t offset[2][2] =
    {
        {Addr3, Addr2},
        {Addr1, Addr2}
    };
    uchar_t toDs = GetToDs();
    uchar_t fromDs = GetFromDs();
    return Mac(buf.get() + offset[toDs][fromDs]);
}

Mac H802dot11::GetDestMac() const
{
    static uchar_t offset[2][2] =
    {
        {Addr1, Addr1},
        {Addr3, Addr3}
    };
    uchar_t toDs = GetToDs();
    uchar_t fromDs = GetFromDs();
    return Mac(buf.get() + offset[toDs][fromDs]);
}

ManagementFrame& H802dot11::GetManagementFrame()
{
    assert(GetType() == ManagementFrameType);
    if (managementFrame != nullptr)
    {
        return *managementFrame;
    }

    uchar_t type = (GetSubtype() << 2) | GetType();
    map<uchar_t, pair<FrameFactor, size_t>>::iterator iter;
    iter = classFactor.find(type);
    assert(iter != classFactor.end());
    managementFrame = iter->second.first(buf, iter->second.second, frameSize - iter->second.second);

    return *managementFrame;
}

ostream& operator << (ostream& os, H802dot11 const& h802dot11)
{
    h802dot11.Put(os);
    return os;
}
CxxEndNameSpace

