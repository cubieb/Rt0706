#include "SystemInclude.h"
#include "SystemError.h"
#include "Common.h"
#include "H802dot11.h"

using namespace std;
CxxBeginNameSpace(Router)

/*******************************/
H802dot11::H802dot11(const shared_ptr<uchar_t>& theBuf, size_t theBufSize)
    : buf(theBuf), bufSize(theBufSize)
{}

H802dot11::~H802dot11() 
{}

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

uchar_t* H802dot11::GetBufPtr() const
{
    return buf.get();
}

size_t H802dot11::GetBufSize() const
{
    return bufSize;
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

/**********************class ManagementFrame**********************/
ManagementFrame::ManagementFrame(const shared_ptr<uchar_t>& buf, size_t bufSize)
    : H802dot11(buf, bufSize)
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
    H802dot11::Put(os);

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

/**********************class DataFrame**********************/
DataFrame::DataFrame(const shared_ptr<uchar_t>& buf, size_t bufSize)
    : H802dot11(buf, bufSize)
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
    H802dot11::Put(os);
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

/**********************class CreateManagementFrame**********************/
template<uchar_t Subtype>
H802dot11* CreateManagementFrame(const std::shared_ptr<uchar_t>& buf, size_t bufSize,
                                 uchar_t subtype)
{
    /* default, check if this is a AssociationRequest frame. */
    if (subtype == AssociationRequest)
        return new AssociationRequestFrame(buf, bufSize);

    return nullptr;
}

template<>
H802dot11* CreateManagementFrame<AssociationResponse>(const std::shared_ptr<uchar_t>& buf, size_t bufSize,
                                                     uchar_t subtype)
{
    /* default, check if this is a AssociationRequest frame. */
    if (subtype == AssociationResponse)
        return nullptr;

    return CreateManagementFrame<AssociationResponse - 1>(buf, bufSize, subtype);
}

template<>
H802dot11* CreateManagementFrame<ReassociationRequest>(const std::shared_ptr<uchar_t>& buf, size_t bufSize,
                                                       uchar_t subtype)
{
    /* default, check if this is a AssociationRequest frame. */
    if (subtype == ReassociationRequest)
        return nullptr;

    return CreateManagementFrame<ReassociationRequest - 1>(buf, bufSize, subtype);
}

template<>
H802dot11* CreateManagementFrame<ReassociationResponse>(const std::shared_ptr<uchar_t>& buf, size_t bufSize,
                                                        uchar_t subtype)
{
    /* default, check if this is a AssociationRequest frame. */
    if (subtype == ReassociationResponse)
        return nullptr;

    return CreateManagementFrame<ReassociationResponse - 1>(buf, bufSize, subtype);
}

template<>
H802dot11* CreateManagementFrame<ProbeRequest>(const std::shared_ptr<uchar_t>& buf, size_t bufSize,
                                               uchar_t subtype)
{
    /* default, check if this is a AssociationRequest frame. */
    if (subtype == ProbeRequest)
        return (new ProbeRequestFrame(buf, bufSize));

    return CreateManagementFrame<ProbeRequest - 1>(buf, bufSize, subtype);
}

template<>
H802dot11* CreateManagementFrame<ProbeResponse>(const std::shared_ptr<uchar_t>& buf, size_t bufSize,
                                                uchar_t subtype)
{
    /* default, check if this is a AssociationRequest frame. */
    if (subtype == ProbeResponse)
        return (new ProbeResponseFrame(buf, bufSize));

    return CreateManagementFrame<ProbeResponse - 1>(buf, bufSize, subtype);
}

template<>
H802dot11* CreateManagementFrame<Beacon>(const std::shared_ptr<uchar_t>& buf, size_t bufSize,
                                         uchar_t subtype)
{
    /* default, check if this is a AssociationRequest frame. */
    if (subtype == Beacon)
        return (new BeaconFrame(buf, bufSize));

    return CreateManagementFrame<Beacon - 1>(buf, bufSize, subtype);
}

template<uchar_t Type>
H802dot11* CreateH802dot11Frame(const std::shared_ptr<uchar_t>& buf, size_t bufSize,
                                uchar_t type, uchar_t subtype)
{
    /* default, check if this is a ManagementFrameType frame. */
    if (type == ManagementFrameType)
        return CreateManagementFrame<Beacon>(buf, bufSize, subtype);

    return nullptr;
}

template<>
H802dot11* CreateH802dot11Frame<ControlFrameType>(const std::shared_ptr<uchar_t>& buf, size_t bufSize,
                                                  uchar_t type, uchar_t subtype)
{
    if (type == ControlFrameType)
        return nullptr;

    return CreateH802dot11Frame<ControlFrameType - 1>(buf, bufSize, type, subtype);
}

template<>
H802dot11* CreateH802dot11Frame<DataFrameType>(const std::shared_ptr<uchar_t>& buf, size_t bufSize,
                                               uchar_t type, uchar_t subtype)
{
    if (type == DataFrameType)
        return (new DataFrame(buf, bufSize));

    return CreateH802dot11Frame<DataFrameType - 1>(buf, bufSize, type, subtype);
}

template<>
H802dot11* CreateH802dot11Frame<ReservedFrameType>(const std::shared_ptr<uchar_t>& buf, size_t bufSize,
                                                   uchar_t type, uchar_t subtype)
{
    if (type == ReservedFrameType)
        return nullptr;

    return CreateH802dot11Frame<ReservedFrameType - 1>(buf, bufSize, type, subtype);
}

H802dot11* CreateFrame(const std::shared_ptr<uchar_t>& buf, size_t bufSize)
{
    uchar_t *ptr = buf.get();
    uchar_t type = (ptr[FrameControl] >> 2) & 0x3;
    uchar_t subtype = (ptr[FrameControl] >> 4) & 0xF;

    return CreateH802dot11Frame<ReservedFrameType>(buf, bufSize, type, subtype);
}

CxxEndNameSpace

