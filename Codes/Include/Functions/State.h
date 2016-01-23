
#ifndef _State_h_
#define _State_h_

#include "SystemInclude.h"
#include "Interface.h"

class StateMachine;

/**
 * Represents a particular state machines state base class.
 *
 * @tparam StateMachineImpl The state machine implementation type.
 * @tparam Interface Specifies the internal interface of state implementations for the state
 *                machine.
 */
class State: public Interface
{
public:    
    /**
     * Constructor for class State.
     */
    State()
    {}
    /**
     * Destructor for class State.
     */
    virtual ~State() {}

    /**
     * Called by the containing state machine when the state is entered.
     * @param context A pointer to the containing state machine.
     */
    virtual void Enter()
    {}

    /**
     * Called by the containing state machine when the state is left.
     * @param context A pointer to the containing state machine.
     */
    virtual void Exit()
    {}
    
    /**
     * Called by the containing state machine after the state was entered.
     * @param context A pointer to the containing state machine.
     */
    virtual void Start()
    {}

    /**
     * Called by the containing state machine before the state is left.
     * @param context A pointer to the containing state machine.
     */
    virtual void End() 
    {}
    
    /**
     * Called by the containing state machine when a higher priority task arise.
     * @param context A pointer to the containing state machine.
     */
    virtual void Pause() 
    {}

    /**
     * Called by the containing state machine when current task have the highest priority .
     * @param context A pointer to the containing state machine.
     */
    virtual void Continue() 
    {}
};


#endif