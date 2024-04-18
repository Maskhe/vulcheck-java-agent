package cn.bestsec.vulcheck.agent.advice;

import cn.bestsec.vulcheck.spy.Dispatcher;
import cn.bestsec.vulcheck.spy.DispatcherHandler;
import net.bytebuddy.asm.Advice;

import java.lang.reflect.Executable;

/**
 * 静态方法或者构造方法类的sink节点使用该Advice处理
 * @author hjx
 * @since 2024/4/3
 */
public class SinkWithoutThisAdvice {
    @Advice.OnMethodEnter
    public static void enter(@Advice.Origin Class<?> cls, @Advice.Origin Executable exe, @Advice.AllArguments Object[] args){
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        dispatcher.enterSink(cls, null, exe, args);
    }

    @Advice.OnMethodExit
    public static void exit(){
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        dispatcher.exitSink();
    }
}
