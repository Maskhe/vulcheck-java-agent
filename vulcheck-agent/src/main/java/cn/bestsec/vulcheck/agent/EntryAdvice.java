package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.spy.Dispatcher;
import cn.bestsec.vulcheck.spy.DispatcherHandler;
import net.bytebuddy.asm.Advice;
/**
 * @author hjx
 * @since 2024/1/2
 * 入口方法增强逻辑
 */
public class EntryAdvice {
    @Advice.OnMethodEnter
    public static void enter() {
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        dispatcher.enterHttp();
    }

    @Advice.OnMethodExit
    public static void exit() {
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        dispatcher.exitHttp();
    }
}
