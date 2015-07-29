#ifndef _PktDbWrapper_h_
#define _PktDbWrapper_h_

CxxBeginNameSpace(Router)
#define TcpDumpMagic            0xA1B2C3D4

class H802dot11;
extern H802dot11* CreateFrame(const std::shared_ptr<uchar_t>& buf, size_t bufSize);;
template<typename PktType>
class PktDbWrapper
{
public:
    typedef typename std::remove_reference<PktType>::type Pkt;
    typedef std::function<void(PktType*)> Trigger;
    
    PktDbWrapper(Trigger theTrigger)
        : filename("../Packets/aircrack-ng-ptw.cap"), trigger(theTrigger)
    {}

    virtual void Start() const = 0;

protected:
    std::string filename;
    Trigger trigger;
};

class PcapFile
{
public:
    PcapFile(const char *fileName);
    size_t GetHeaderSize();
    size_t GetFileSize();

public:
    uint32_t magic;
    uint16_t versionMajor;
    uint16_t versionMinor;
    int32_t  reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
    uint32_t linkType;

private:
    PcapFile() {}
    size_t fileSize;
};

class PcapPacketHeader
{
public:
    PcapPacketHeader(const char *fileName, size_t offset);
    size_t GetSize();

public:
    struct timeval ts;
    uint32_t       caplen;/* length of portion present */
    uint32_t       len;   /* length this packet (off wire) */
};

template<typename PktType>
class PcapPktDbWrapper: public PktDbWrapper<PktType>
{
public:
    PcapPktDbWrapper(Trigger trigger): PktDbWrapper(trigger)
    {}

    void Start() const
    {
        PcapFile pcapFile(filename.c_str());
        if (pcapFile.linkType != LinkType::ieee802dot11)
        {
            errstrm << "bad file type." << endl;
            return;
        }

        if (pcapFile.linkType != LinkType::ieee802dot11)
        {
            errstrm << "bad file type." << endl;
            return;
        }

        size_t offset = pcapFile.GetHeaderSize();
        while (offset < pcapFile.GetFileSize())
        {
            PcapPacketHeader pcapPacketHeader(filename.c_str(), offset);
            size_t packetOff = offset + pcapPacketHeader.GetSize();
            offset = offset + pcapPacketHeader.caplen + pcapPacketHeader.GetSize();

            if (pcapPacketHeader.caplen < 24)
            {
                continue;
            }

            shared_ptr<uchar_t> buf(new uchar_t[pcapPacketHeader.caplen], []( uchar_t *p ) { delete[] p; });
            fstream pcapFile(filename.c_str(), ios_base::in | ios::binary);
            pcapFile.seekp(packetOff);
            pcapFile.read(reinterpret_cast<char*>(buf.get()), pcapPacketHeader.caplen);

            PktType* pkt = CreateFrame(buf, pcapPacketHeader.caplen);

            trigger(pkt);
        }        
    }

private:
};

CxxEndNameSpace
#endif