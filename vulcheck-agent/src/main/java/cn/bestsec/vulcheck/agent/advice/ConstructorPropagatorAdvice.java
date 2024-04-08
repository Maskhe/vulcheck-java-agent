package cn.bestsec.vulcheck.agent.advice;

import cn.bestsec.vulcheck.spy.Dispatcher;
import cn.bestsec.vulcheck.spy.DispatcherHandler;
import cn.bestsec.vulcheck.spy.OriginCaller;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import java.lang.reflect.Executable;

public class ConstructorPropagatorAdvice {
    @Advice.OnMethodEnter
    public static void enter(){
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        dispatcher.enterConstructorPropagator();
    }

    @Advice.OnMethodExit
    public static void exit(@Advice.Origin Class<?> cls, @Advice.This Object caller, @Advice.Origin Executable exe,
                            @Advice.AllArguments Object[] args){
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        dispatcher.exitConstructorPropagator(cls, caller, exe, args);
    }
}
