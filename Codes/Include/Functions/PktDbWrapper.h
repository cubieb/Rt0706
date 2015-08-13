#ifndef _PktDbWrapper_h_
#define _PktDbWrapper_h_

#include "ContainerBase.h"

CxxBeginNameSpace(Router)
#define TcpDumpMagic            0xA1B2C3D4

enum LinkType: uint32_t
{
    Ethernet       = 1,
    ieee802dot11   = 105,
    PrismHeader    = 119,
    RadiotapHeader = 127,
    PpiHeader      = 192
};

/**********************class PcapFile**********************/
struct PcapFileHeader
{
    uint32_t magic;
    uint16_t versionMajor;
    uint16_t versionMinor;
    int32_t  reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
    uint32_t linkType;
};

/**********************class PcapPacketHeader**********************/
struct PcapPacketHeader
{
    struct timeval ts;
    uint32_t       caplen;/* length of portion present */
    uint32_t       len;   /* length this packet (off wire) */
};

/**********************class PcapFileReader**********************/
class PcapFileReader
{
public:
    PcapFileReader(const char *fileName);
    size_t Read(std::shared_ptr<uchar_t>& out);

private:
    PcapFileReader();
    std::fstream fs;
};

/**********************class PktDbWrapper**********************/
//refer to class ContainerValue
class PktDbWrapper: public ContainerBase
{
public:
    typedef std::list<std::pair<std::shared_ptr<uchar_t>, size_t>> Repository;

    typedef Repository::iterator NodePtr;
    typedef Repository::value_type value_type;
    typedef Repository::size_type size_type;
    typedef Repository::difference_type difference_type;
    typedef Repository::pointer pointer;
    typedef Repository::const_pointer const_pointer;
    typedef Repository::reference reference;
    typedef Repository::const_reference const_reference;

    PktDbWrapper()
    {}

    static NodePtr GetNextNodePtr(NodePtr ptr)
    {   // return reference to successor pointer in node
        return ++ptr;
    }

    static reference GetValue(NodePtr ptr)
    {
        return *ptr;
    }

protected:
    std::list<std::pair<std::shared_ptr<uchar_t>, size_t>>  repository;
};

/**********************class PcapPktDbWrapper**********************/
//ContainerAlloc + Container
class PcapPktDbWrapper: public PktDbWrapper
{
public:
    typedef PcapPktDbWrapper MyType;
    typedef PktDbWrapper     MyBase;

    typedef Iterator<PcapPktDbWrapper>::MyIter      iterator;
    typedef ConstIterator<PcapPktDbWrapper>::MyIter const_iterator;

    typedef MyBase::value_type value_type;
    typedef MyBase::size_type size_type;
    typedef MyBase::difference_type difference_type;
    typedef MyBase::pointer pointer;
    typedef MyBase::const_pointer const_pointer;
    typedef MyBase::reference reference;
    typedef MyBase::const_reference const_reference;

    PcapPktDbWrapper(const char *fileName);    
    ~PcapPktDbWrapper(); // destroy head node

    void AllocProxy();   // construct proxy from _Alnod
    void FreeProxy();    // destroy proxy

    iterator begin();
    iterator end();
};

CxxEndNameSpace
#endif