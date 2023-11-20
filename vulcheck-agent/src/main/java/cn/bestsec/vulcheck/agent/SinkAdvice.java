package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.spy.Dispatcher;
import cn.bestsec.vulcheck.spy.DispatcherHandler;
import net.bytebuddy.asm.Advice;

import java.lang.reflect.Executable;
import java.util.HashMap;
import java.util.HashSet;

/**
 * 污点汇聚节点处理逻辑
 * @author hjxin
 * @since 2023/11/15
 */
public class SinkAdvice {
    @Advice.OnMethodEnter
    public static void enter(@Advice.Origin Class<?> cls, @Advice.This Object caller, @Advice.Origin Executable exe, @Advice.AllArguments Object[] args, @Advice.Origin("#m") String methodName,
                             @Advice.Origin("#t") Class<?> declaringType,
                             @Advice.Origin("#t") String simpleTypeName, @Advice.Return Object ret){
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        dispatcher.enterSink(cls, caller, exe, args, ret);

    }

    @Advice.OnMethodExit
    public static void exit(){
//        System.out.println("退出sink节点");
    }
}
