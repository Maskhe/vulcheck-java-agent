package cn.bestsec.vulcheck.agent.advice;

import cn.bestsec.vulcheck.spy.Dispatcher;
import cn.bestsec.vulcheck.spy.DispatcherHandler;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import java.lang.reflect.Executable;


public class PropagatorWithoutThisAdvice {
    @Advice.OnMethodEnter
    public static void enter(){
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        dispatcher.enterPropagatorWithoutThis();
    }

    @Advice.OnMethodExit
    public static void exit(@Advice.Origin Class<?> cls, @Advice.Origin Executable exe,
                            @Advice.AllArguments Object[] args, @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object ret){
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        dispatcher.exitPropagatorWithoutThis(cls, exe, args, ret);
    }
}
