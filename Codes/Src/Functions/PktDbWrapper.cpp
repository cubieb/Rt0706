#include "SystemInclude.h"
#include "Common.h"
#include "Debug.h"
#include "SystemError.h" 

#include "PktDbWrapper.h"

#ifdef _DEBUG
#define new DEBUG_CLIENTBLOCK
#endif

using namespace std;
CxxBeginNameSpace(Router)

/**********************class PcapFileReader**********************/
PcapFileReader::PcapFileReader(const char *fileName)
    : fs(fileName, ios_base::in  | ios::binary)
{
    if (fs == nullptr)
    {
        throw system_error(system_error_t::file_not_exists);
    }

    PcapFileHeader file;
    fs.read(reinterpret_cast<char *>(&file.magic), sizeof(file.magic));
    fs.read(reinterpret_cast<char *>(&file.versionMajor), sizeof(file.versionMajor));
    fs.read(reinterpret_cast<char *>(&file.versionMinor), sizeof(file.versionMinor));
    fs.read(reinterpret_cast<char *>(&file.reserved1), sizeof(file.reserved1));
    fs.read(reinterpret_cast<char *>(&file.reserved2), sizeof(file.reserved2));
    fs.read(reinterpret_cast<char *>(&file.reserved3), sizeof(file.reserved3));
    fs.read(reinterpret_cast<char *>(&file.linkType), sizeof(file.linkType));

    if (file.magic != TcpDumpMagic || file.linkType != LinkType::ieee802dot11)
    {
        throw system_error(system_error_t::bad_file_type);
    }
}

size_t PcapFileReader::Read(shared_ptr<uchar_t>& out)
{
    if (fs.peek() == EOF) 
    {
        return 0;
    }

    PcapPacketHeader header;
    fs.read(reinterpret_cast<char *>(&header.ts), sizeof(header.ts));
    fs.read(reinterpret_cast<char *>(&header.caplen), sizeof(header.caplen));
    fs.read(reinterpret_cast<char *>(&header.len), sizeof(header.len));

    uchar_t *ptr = new uchar_t[header.caplen];
    out.reset(ptr, UcharDeleter());
    fs.read(reinterpret_cast<char *>(out.get()), header.caplen);

    return header.caplen;
}

/**********************class PcapPktDbWrapper**********************/
PcapPktDbWrapper::PcapPktDbWrapper(const char *fileName)
{
    AllocProxy();

    PcapFileReader reader(fileName);
    shared_ptr<uchar_t> buffer;
    size_t size;
    while((size = reader.Read(buffer)) != 0)
    {
        repository.push_back(make_pair(buffer, size));
    }
}

PcapPktDbWrapper::~PcapPktDbWrapper()
{   
    FreeProxy();
}

void PcapPktDbWrapper::AllocProxy()
{
    myProxy = new ContainerProxy;
    myProxy->myContainer = this;
}

void PcapPktDbWrapper::FreeProxy()
{
    OrphanAll();
    delete myProxy;
    myProxy = nullptr;
}

PcapPktDbWrapper::iterator PcapPktDbWrapper::begin()
{
    return iterator(this, NodePtr(repository.begin()));
}

PcapPktDbWrapper::iterator PcapPktDbWrapper::end()
{
    return iterator(this, NodePtr(repository.end()));
}
CxxEndNameSpace