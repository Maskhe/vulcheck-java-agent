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
    public static void enter(@Advice.Origin Class<?> cls, @Advice.This Object caller, @Advice.Origin Executable exe, @Advice.AllArguments Object[] args){
//        System.out.println("进入传播节点");
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        dispatcher.enterPropagatorWithNoRet(cls, caller, exe, args);
    }

    @Advice.OnMethodExit
    public static void exit(@Advice.Origin Class<?> cls, @Advice.This Object caller, @Advice.Origin Executable exe, @Advice.AllArguments Object[] args){
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        dispatcher.exitPropagatorWithNoRet(cls, caller, exe, args);
//        System.out.println("退出传播节点");
    }
}
