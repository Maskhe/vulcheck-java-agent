package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.spy.Dispatcher;
import cn.bestsec.vulcheck.spy.DispatcherHandler;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import java.lang.reflect.Executable;
import java.util.HashMap;
import java.util.HashSet;

/**
 * @author hjxin
 * @description 污点来源节点处理逻辑
 * @since 2023/11/13
 */

public class SourceAdvice {

    @Advice.OnMethodEnter
    public static void enter(){
        System.out.println("进入source节点");
    }

    @Advice.OnMethodExit
    public static void exit(@Advice.Origin Class<?> cls, @Advice.Origin Executable exe, @Advice.AllArguments Object[] args, @Advice.Return(typing = Assigner.Typing.DYNAMIC) String ret){
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        dispatcher.exitSource(cls, exe, args, ret);
    }

}
