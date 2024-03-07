package cn.bestsec.vulcheck.agent.advice;

import cn.bestsec.vulcheck.spy.Dispatcher;
import cn.bestsec.vulcheck.spy.DispatcherHandler;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import java.lang.reflect.Executable;

public class SanitizerAdvice {
    @Advice.OnMethodEnter
    public static void enter(){
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
//        dispatcher.enterPropagator();
    }

    @Advice.OnMethodExit
    public static void exit(@Advice.Origin Class<?> cls, @Advice.This Object caller, @Advice.Origin Executable exe, @Advice.AllArguments Object[] args,
                            @Advice.Origin("#t") Class<?> declaringType,
                            @Advice.Origin("#t") String simpleTypeName, @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object ret){
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
//        dispatcher.exitPropagator(cls, caller, exe, args, ret, );
    }
}
