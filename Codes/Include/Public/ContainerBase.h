#ifndef _ContainerBase_h_
#define _ContainerBase_h_

struct ContainerBase0
{   // base of all containers
    void OrphanAll()
    {   // orphan all iterators
    }

    void SwapAll(ContainerBase0&)
    {   // swap all iterators
    }
};

struct IteratorBase0
{   // base of all iterators
    void Adopt(const void *)
    {   // adopt this iterator by parent
    }

    const ContainerBase0 *GetContainer() const
    {   // get owning container
        return (0);
    }
};

struct ContainerBase;
struct IteratorBase;

//stl: struct _Container_proxy
struct ContainerProxy
{   // store head of iterator chain and back pointer
    ContainerProxy(): myContainer(0), myFistIter(0)
    {   // construct from pointers
    }

    const ContainerBase *myContainer;
    IteratorBase *myFistIter;
};

//stl: struct _Container_base12;
struct ContainerBase
{   // store pointer to ContainerProxy
    ContainerBase(): myProxy(0)
    {   // construct childless container
    }

    ContainerBase(const ContainerBase&): myProxy(0)
    {   // copy a container
    }

    ContainerBase& operator=(const ContainerBase&)
    {   // assign a container
        return (*this);
    }

    ~ContainerBase()
    {   // destroy the container
        OrphanAll();
    }

    IteratorBase **GetpFirst() const
    {   // get address of iterator chain
        return (myProxy == nullptr ? nullptr : &myProxy->myFistIter);
    }

    // orphan all iterators
    void OrphanAll();

    // swap all iterators
    void SwapAll(ContainerBase&);

    ContainerProxy *myProxy;
};

//stl:  struct _Iterator_base12;
struct IteratorBase 
{   // store links to container proxy, next iterator
    IteratorBase(): myProxy(nullptr), myNextIter(nullptr)
    {   // construct orphaned iterator
    }

    IteratorBase(const IteratorBase& right)
        : myProxy(nullptr), myNextIter(nullptr)
    {   // copy an iterator
        *this = right;
    }

    IteratorBase& operator=(const IteratorBase& right)
    {   // assign an iterator
        if (myProxy == right.myProxy)
        {
            ;
        }
        else if (right.myProxy != 0)
            Adopt(right.myProxy->myContainer);
        else
        {   // becoming invalid, disown current parent
            OrphanMe();
        }
        return (*this);
    }

    ~IteratorBase()
    {   // destroy the iterator
#ifdef _DEBUG
        OrphanMe();
#endif
    }

    void Adopt(const ContainerBase *parent)
    {   // adopt this iterator by parent
        if (parent == nullptr)
        {   // no future parent, just disown current parent
            OrphanMe();
        }
        else
        {   // have a parent, do adoption
            ContainerProxy *parentProxy = parent->myProxy;
#ifdef _DEBUG
            if (myProxy != parentProxy)
            {	// change parentage
                OrphanMe();
                myNextIter = parentProxy->myFistIter;
                parentProxy->myFistIter = this;
                myProxy = parentProxy;
            }
#else  //#ifdef _DEBUG
            myProxy = parentProxy;
#endif  //#else  #ifdef _DEBUG
        }
    }

    void ClearContainer()
    {   // disown owning container
        myProxy = nullptr;
    }

    const ContainerBase *GetContainer() const
    {   // get owning container
        return (myProxy == nullptr ? nullptr : myProxy->myContainer);
    }

    IteratorBase **GetNextIter()
    {   // get address of remaining iterator chain
        return (&myNextIter);
    }

    void OrphanMe()
    {   // cut ties with parent
#ifdef _DEBUG
        if (myProxy != 0)
        {	// adopted, remove self from list
            IteratorBase **next = &myProxy->myFistIter;
            while (*next != 0 && *next != this)
                next = &(*next)->myNextIter;

            assert(*next != 0); //Iterator list corrupted.
            *next = myNextIter;
            myProxy = 0;
        }
#endif  //#ifdef _DEBUG
    }

    ContainerProxy *myProxy;
    IteratorBase *myNextIter;
};

inline void ContainerBase::OrphanAll()
{
#ifdef _DEBUG
    if (myProxy != 0)
    {	// proxy allocated, drain it
        for (IteratorBase **next = &myProxy->myFistIter;
            *next != 0; 
            *next = (*next)->myNextIter)
            (*next)->myProxy = 0;
        myProxy->myFistIter = 0;
    }
#endif  //#ifdef _DEBUG
}

inline void ContainerBase::SwapAll(ContainerBase& right)
    {   // swap all iterators
    ContainerProxy *tmp = myProxy;
    myProxy = right.myProxy;
    right.myProxy = tmp;

    if (myProxy != 0)
        myProxy->myContainer = (ContainerBase*)this;
    if (right.myProxy != 0)
        right.myProxy->myContainer = (ContainerBase*)&right;
    }

/**********************class ConstIterator**********************/
template<typename ContainerType>
class ConstIterator: public IteratorBase    
{
public:
    typedef ContainerType                MyContainer;
    
    typedef IteratorBase                 MyBase;
    typedef ConstIterator<ContainerType> MyIter;
    typedef std::forward_iterator_tag iterator_category;

    typedef typename MyContainer::NodePtr NodePtr;
    typedef typename MyContainer::value_type value_type;
    typedef typename MyContainer::size_type size_type;
    typedef typename MyContainer::difference_type difference_type;
    typedef typename MyContainer::const_pointer pointer;
    typedef typename MyContainer::const_reference reference;

    ConstIterator(): MyBase(), ptr(NodePtr())
    {}

    ConstIterator(const MyContainer *container, NodePtr thePtr)
        : ptr(thePtr)
    {
        this->Adopt(container);
    }

    reference operator*() const
    {   // return designated value
#ifdef _DEBUG
        if (this->GetContainer() == nullptr
            || this->ptr == nullptr
            || this->ptr == ((MyContainer *)this->GetContainer())->GetMyHead())
        {   // report error
             //list iterator not incrementable;
             assert(false);
        }
#endif
        return (MyContainer::GetValue(this->ptr));
    }
    
    pointer operator->() const
    {   // return pointer to class object
        return (std::pointer_traits<pointer>::pointer_to(**this));
    }

    MyIter& operator++()
    {   // pre-increment
#ifdef _DEBUG
         if (this->GetContainer() == nullptr
                || this->ptr == nullptr
                || this->ptr == ((MyContainer *)this->GetContainer())->GetMyHead())
         {   // report error
             //list iterator not incrementable;
             assert(false);
         }
#endif
        ptr = MyContainer::GetNextNodePtr(this->ptr);
        return (*this);
    }

    MyIter operator++(int)
    {   // post-increment
        MyIter tmp = *this;
        ++*this;
        return (tmp);
    }

    bool operator==(const MyIter& right) const
    {   // test for iterator equality
#ifdef _DEBUG
        assert(this->GetContainer() != nullptr
            && this->GetContainer() == right.GetContainer());
#endif

        return (this->ptr == right.ptr);
    }

    bool operator!=(const MyIter& right) const
    {   // test for iterator inequality
        return (!(*this == right));
    }

    NodePtr GetMyNode() const
    {   // return node pointer
        return (ptr);
    }

protected:
    NodePtr ptr;
};

/**********************class Iterator**********************/
template<typename ContainerType>
class Iterator: public ConstIterator<ContainerType> 
{
public:
    typedef ConstIterator<ContainerType> MyBase;
    typedef Iterator<ContainerType>      MyIter;

    typedef std::bidirectional_iterator_tag iterator_category;

    typedef typename MyContainer::NodePtr NodePtr;
    typedef typename MyContainer::value_type value_type;
    typedef typename MyContainer::size_type size_type;
    typedef typename MyContainer::difference_type difference_type;
    typedef typename MyContainer::pointer pointer;
    typedef typename MyContainer::reference reference;
    
    Iterator()
    {}

    Iterator(MyContainer *container, NodePtr ptr)
        : MyBase(container, ptr)
    {}

    reference operator*() const
    {
        return ((reference)**(MyBase *)this);
    }

    pointer operator->() const
    {   // return pointer to class object
        return (std::pointer_traits<pointer>::pointer_to(**this));
    }

    MyIter& operator++()
    {   // pre-increment
        ++(*(MyBase *)this);
        return (*this);
    }

    MyIter operator++(int)
    {   // post-increment
        MyIter tmp = *this;
        ++*this;
        return (tmp);
    }
};

#endif /* _ContainerBase_h_ */
