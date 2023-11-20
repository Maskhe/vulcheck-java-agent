package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.spy.Dispatcher;
import cn.bestsec.vulcheck.spy.DispatcherHandler;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import java.lang.reflect.Executable;

/**
 * 污点传播节点处理逻辑
 * @author hjxin
 * @since 2023/11/15
 */
public class PropagatorWithNoRetAdvice {
    @Advice.OnMethodEnter
    public static void enter(){
//        System.out.println("进入propagator节点");
    }

    @Advice.OnMethodExit
    public static void exit(@Advice.Origin Class<?> cls, @Advice.This Object caller, @Advice.Origin Executable exe, @Advice.AllArguments Object[] args, @Advice.Origin("#m") String methodName,
                            @Advice.Origin("#t") Class<?> declaringType,
                            @Advice.Origin("#t") String simpleTypeName){
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        dispatcher.exitPropagatorWithNoRet(cls, caller, exe, args);
    }
}
