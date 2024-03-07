package cn.bestsec.vulcheck.agent.advice;

import cn.bestsec.vulcheck.spy.Dispatcher;
import cn.bestsec.vulcheck.spy.DispatcherHandler;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import java.lang.reflect.Executable;

/**
 * 污点传播节点处理逻辑
 * @author hjxin
 * @since 2023/11/15
 */
public class PropagatorAdvice {

    @Advice.OnMethodEnter
    public static void enter(@Advice.This Object caller, @Advice.Local("thisObject") Object thisObject){
        thisObject = caller;
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        dispatcher.enterPropagator(caller, thisObject);
    }

    @Advice.OnMethodExit
    public static void exit(@Advice.Origin Class<?> cls, @Advice.This Object caller, @Advice.Origin Executable exe, @Advice.AllArguments Object[] args,
                            @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object ret, @Advice.Local("thisObject") Object thisObject){
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        dispatcher.exitPropagator(cls, caller, exe, args, ret, thisObject);
    }
}
