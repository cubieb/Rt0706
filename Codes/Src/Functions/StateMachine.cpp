#include "SystemInclude.h"

#include "StateMachine.h"

/**********************class StateMachine**********************/
StateMachine::StateMachine(State *state): state(state)
{  }

StateMachine::~StateMachine()
{}

void StateMachine::ChangeState(State* newState)
{
    ExitCurrentState();
    SetState(newState);
    EnterNewState();
}

void StateMachine::SetState(State* newState)
{
    state.reset(newState);
}

void StateMachine::EnterNewState()
{
    state->Enter();
    state->Start();
}

void StateMachine::ExitCurrentState()
{
    if (state != nullptr)
    {
        state->End();
        state->Exit();
    }
}