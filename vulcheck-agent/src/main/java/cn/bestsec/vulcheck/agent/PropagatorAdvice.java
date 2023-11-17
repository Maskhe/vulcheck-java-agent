package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.spy.Dispatcher;
import cn.bestsec.vulcheck.spy.DispatcherHandler;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import java.lang.reflect.Executable;
import java.util.HashMap;
import java.util.HashSet;

public class PropagatorAdvice {
    @Advice.OnMethodEnter
    public static void enter(){
        System.out.println("进入propagator节点");
    }

    @Advice.OnMethodExit
    public static void exit(@Advice.Origin Class<?> cls, @Advice.Origin Executable exe, @Advice.AllArguments Object[] args, @Advice.Origin("#m") String methodName,
                            @Advice.Origin("#t") Class<?> declaringType,
                            @Advice.Origin("#t") String simpleTypeName, @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object ret){
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        dispatcher.exitPropagator(cls, exe, args, ret);
    }
}
