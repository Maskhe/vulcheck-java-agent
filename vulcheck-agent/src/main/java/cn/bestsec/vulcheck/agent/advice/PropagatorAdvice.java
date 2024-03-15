package cn.bestsec.vulcheck.agent.advice;

import cn.bestsec.vulcheck.spy.Dispatcher;
import cn.bestsec.vulcheck.spy.DispatcherHandler;
import cn.bestsec.vulcheck.spy.OriginCaller;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import java.lang.reflect.Executable;
import java.util.HashMap;

/**
 * 污点传播节点处理逻辑
 * @author hjxin
 * @since 2023/11/15
 */
public class PropagatorAdvice {

    @Advice.OnMethodEnter
    public static void enter(@Advice.Origin Class<?> cls, @Advice.This Object caller, @Advice.Origin Executable exe,
                             @Advice.AllArguments Object[] args, @Advice.Local("originalCaller") OriginCaller originalCaller){
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        originalCaller = dispatcher.enterPropagator(cls, caller, exe, args);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(@Advice.Origin Class<?> cls, @Advice.This Object caller, @Advice.Origin Executable exe, @Advice.AllArguments Object[] args,
                            @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object ret, @Advice.Local("originalCaller")OriginCaller originalCaller, @Advice.Thrown Throwable throwable){
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        dispatcher.exitPropagator(cls, caller, exe, args, ret, originalCaller);


//        if (throwable != null) {
//            System.out.println("test"+ throwable.getMessage());
//        }
    }
}
