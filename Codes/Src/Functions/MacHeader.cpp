#include "SystemInclude.h"
#include "SystemError.h"
#include "Common.h"
#include "MacHeader.h"

using namespace std;
CxxBeginNameSpace(Router)

/*******************************/
MacHeader::MacHeader(const shared_ptr<uchar_t>& theBuf, size_t theBufSize)
    : buf(theBuf), bufSize(theBufSize)
{}

MacHeader::~MacHeader() 
{}

uchar_t MacHeader::GetProtocolBits() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = ptr[FrameControl] & 0x3;
    return value;
}

uchar_t MacHeader::GetTypeBits() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = (ptr[FrameControl] >> 2) & 0x3;
    return value;
}

uchar_t MacHeader::GetSubtypeBits() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = (ptr[FrameControl] >> 4) & 0xF;
    return value;
}

uchar_t MacHeader::GetToDsBit() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = ptr[FrameControl + 1] & 0x1;
    return value;
}

uchar_t MacHeader::GetFromDsBit() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = (ptr[FrameControl + 1] >> 1) & 0x1;
    return value;
}

uchar_t MacHeader::GetMoreTagBit() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = (ptr[FrameControl + 1] >> 2) & 0x1;
    return value;
}

uchar_t MacHeader::GetRetryBit() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = (ptr[FrameControl + 1] >> 3) & 0x1;
    return value;
}

uchar_t MacHeader::GetPowerMgmtBit() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = (ptr[FrameControl + 1] >> 4) & 0x1;
    return value;
}

uchar_t MacHeader::GetMoreDataBit() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = (ptr[FrameControl + 1] >> 5) & 0x1;
    return value;
}

uchar_t MacHeader::GetWepBit() const
{
    uchar_t* ptr = buf.get();
    uchar_t value = (ptr[FrameControl + 1] >> 6) & 0x1;
    return value;
}

uchar_t* MacHeader::GetBufPtr() const
{
    return buf.get();
}

size_t MacHeader::GetBufSize() const
{
    return bufSize;
}

void MacHeader::Put(std::ostream& os) const
{
    os << endl << MemStream<uchar_t>(buf.get(), 32) << endl;

    os << "version = " << (uint_t) GetProtocolBits()
       << ", type = " << (uint_t) GetTypeBits()
       << ", subtype = " << (uint_t) GetSubtypeBits()
       << ", ToDs = " << (uint_t) GetToDsBit()
       << ", FromDs = " << (uint_t) GetFromDsBit() 
       << ", Wep = " << (uint_t) GetWepBit();
}

/**********************class ManagementFrame**********************/
ManagementFrame::ManagementFrame(const shared_ptr<uchar_t>& buf, size_t bufSize)
    : MacHeader(buf, bufSize)
{
}

ManagementFrame::~ManagementFrame()
{}

Mac ManagementFrame::GetDstMac() const
{
    return Mac(buf.get() + Addr1);
}

Mac ManagementFrame::GetSrcMac() const
{
    return Mac(buf.get() + Addr2);
}

Mac ManagementFrame::GetBssid() const
{
    return Mac(buf.get() + Addr3);
}

string ManagementFrame::GetEssid() const
{
    uchar_t* ptr;
    string essid;
    for (ptr = GetFrameBodyPtr() + GetFixedParaSize(); 
         ptr < GetFrameBodyPtr() + GetFrameBodySize(); 
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

uchar_t* ManagementFrame::GetFrameBodyPtr() const
{
    return buf.get() + ManagementHeaderSize;
}

size_t ManagementFrame::GetFrameBodySize() const
{
    return GetBufSize() - ManagementHeaderSize;
}

void ManagementFrame::Put(ostream& os) const
{
    MacHeader::Put(os);

    os << "Da = " << GetDstMac()
        << ", Bssid = " << GetBssid()
        << ", Essid = " << GetEssid();
}

/**********************class AssociationRequestFrame**********************/
AssociationRequestFrame::AssociationRequestFrame(const shared_ptr<uchar_t>& buf, size_t bufSize)
    : ManagementFrame(buf, bufSize)
{}

AssociationRequestFrame::~AssociationRequestFrame()
{}

void AssociationRequestFrame::Put(std::ostream& os) const
{
    ManagementFrame::Put(os);
}

size_t AssociationRequestFrame::GetFixedParaSize() const
{
    return AssociationRequestFixedFieldSize;
}

/**********************class BeaconFrame**********************/
BeaconFrame::BeaconFrame(const shared_ptr<uchar_t>& buf, size_t bufSize)
    : ManagementFrame(buf, bufSize)
{}

BeaconFrame::~BeaconFrame()
{}

void BeaconFrame::Put(std::ostream& os) const
{
    ManagementFrame::Put(os);
}

size_t BeaconFrame::GetFixedParaSize() const
{
    return BeaconFixedFieldSize;
}

/**********************class ProbeRequestFrame**********************/
ProbeRequestFrame::ProbeRequestFrame(const shared_ptr<uchar_t>& buf, size_t bufSize)
    : ManagementFrame(buf, bufSize)
{}

ProbeRequestFrame::~ProbeRequestFrame()
{}

void ProbeRequestFrame::Put(std::ostream& os) const
{
    ManagementFrame::Put(os);
}

size_t ProbeRequestFrame::GetFixedParaSize() const
{
    return ProbeRequestFixedFieldSize;
}

/**********************class ProbeResponseFrame**********************/
ProbeResponseFrame::ProbeResponseFrame(const shared_ptr<uchar_t>& buf, size_t bufSize)
    : ManagementFrame(buf, bufSize)
{}

ProbeResponseFrame::~ProbeResponseFrame()
{}


void ProbeResponseFrame::Put(std::ostream& os) const
{
    ManagementFrame::Put(os);
}

size_t ProbeResponseFrame::GetFixedParaSize() const
{
    return ProbeResponseFixedFieldSize;
}

/**********************class DataFrame**********************/
DataFrame::DataFrame(const shared_ptr<uchar_t>& buf, size_t bufSize)
    : MacHeader(buf, bufSize)
{}

DataFrame::~DataFrame()
{}

uchar_t* DataFrame::GetFrameBodyPtr() const
{
    return GetBufPtr() + GetMacHeaderSize();
}

size_t DataFrame::GetFrameBodySize() const
{
    return GetBufSize() - GetMacHeaderSize();
}

Mac DataFrame::GetDstMac() const
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

void DataFrame::Put(std::ostream& os) const
{
    MacHeader::Put(os);
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

/**********************class CreateMacHeader**********************/
MacHeaderCreatorRgistration(ManagementFrameType, AssociationRequest, AssociationRequestFrame::CreateInstance);
MacHeaderCreatorRgistration(ManagementFrameType, Beacon, BeaconFrame::CreateInstance);
MacHeaderCreatorRgistration(ManagementFrameType, ProbeRequest, ProbeRequestFrame::CreateInstance);
MacHeaderCreatorRgistration(ManagementFrameType, ProbeResponse, ProbeResponseFrame::CreateInstance);

MacHeaderCreatorRgistration(DataFrameType, Data, DataFrame::CreateInstance);
MacHeaderCreatorRgistration(DataFrameType, DataAndCfAck, DataFrame::CreateInstance);
MacHeaderCreatorRgistration(DataFrameType, DataAndCfPoll, DataFrame::CreateInstance);
MacHeaderCreatorRgistration(DataFrameType, DataAndCfAckAndCfPoll, DataFrame::CreateInstance);
MacHeaderCreatorRgistration(DataFrameType, Null, DataFrame::CreateInstance);
MacHeaderCreatorRgistration(DataFrameType, CfAck, DataFrame::CreateInstance);
MacHeaderCreatorRgistration(DataFrameType, CfPoll, DataFrame::CreateInstance);
MacHeaderCreatorRgistration(DataFrameType, CfAckAndCfPoll, DataFrame::CreateInstance);
MacHeaderCreatorRgistration(DataFrameType, QosData, DataFrame::CreateInstance);
MacHeaderCreatorRgistration(DataFrameType, QosDataAndCfAck, DataFrame::CreateInstance);
MacHeaderCreatorRgistration(DataFrameType, QosDataAndCfPoll, DataFrame::CreateInstance);
MacHeaderCreatorRgistration(DataFrameType, QosDataAndCfAckAndCfPoll, DataFrame::CreateInstance);
MacHeaderCreatorRgistration(DataFrameType, QosNull, DataFrame::CreateInstance);
MacHeaderCreatorRgistration(DataFrameType, DataReserved, DataFrame::CreateInstance);
MacHeaderCreatorRgistration(DataFrameType, QosCfPoll, DataFrame::CreateInstance);
MacHeaderCreatorRgistration(DataFrameType, QosCfAckAndCfPoll, DataFrame::CreateInstance);

void MacHeaderFactor::Register(uchar_t type, uchar_t subtype, MacHeaderCreator creator)
{
    uchar_t key = (type << 4) | subtype;
    creatorMap.insert(make_pair(key, creator));
}

MacHeader* MacHeaderFactor::Create(uchar_t type, uchar_t subtype, 
                                   const std::shared_ptr<uchar_t>& buf, size_t bufSize)
{
    uchar_t key = (type << 4) | subtype;
    map<uchar_t, MacHeaderCreator>::iterator iter = creatorMap.find(key);
    if (iter == creatorMap.end())
        return nullptr;

    return iter->second(buf, bufSize);
}

MacHeader* CreateMacHeader(const std::shared_ptr<uchar_t>& buf, size_t bufSize)
{
    uchar_t *ptr = buf.get();
    uchar_t type = (ptr[FrameControl] >> 2) & 0x3;
    uchar_t subtype = (ptr[FrameControl] >> 4) & 0xF;

    MacHeaderFactor& instance = MacHeaderFactor::GetInstance();
    return instance.Create(type, subtype, buf, bufSize);
}

CxxEndNameSpace

