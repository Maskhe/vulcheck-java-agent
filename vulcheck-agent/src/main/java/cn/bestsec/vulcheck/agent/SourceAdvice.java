package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.spy.Dispatcher;
import cn.bestsec.vulcheck.spy.DispatcherHandler;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import java.lang.reflect.Executable;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;

/**
 * 污点来源节点处理逻辑
 * @author hjxin
 * @since 2023/11/13
 */

public class SourceAdvice {

    @Advice.OnMethodEnter
    public static void enter(){
        System.out.println("进入source节点");
    }

    @Advice.OnMethodExit
    public static void exit(@Advice.Origin Class<?> cls, @Advice.This Object caller, @Advice.Origin Executable exe, @Advice.AllArguments Object[] args, @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object ret){
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        dispatcher.exitSource(cls, caller, exe, args, ret);
    }

}
