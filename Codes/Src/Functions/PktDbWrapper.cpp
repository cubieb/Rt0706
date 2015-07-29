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

CxxEndNameSpace