#ifndef _PktDbWrapper_h_
#define _PktDbWrapper_h_

CxxBeginNameSpace(Router)

template<typename PktType>
class PktDbWrapper
{
public:
    typedef typename std::remove_reference<PktType>::type Pkt;
    typedef std::function<void(PktType*)> Trigger;
    
    PktDbWrapper(Trigger theTrigger)
        : trigger(theTrigger)
    {}

    void Start()
    {
        trigger(nullptr);
    }

private:
    std::string filename;
    Trigger trigger;
};

//template<typename PktType, typename PktReceiver>
//class PcapPktDbWrapper: public PktDbWrapper<PktType, PktReceiver>
//{
//public:
//    PcapPktDbWrapper()
//    {}
//
//private:
//};

CxxEndNameSpace
#endif