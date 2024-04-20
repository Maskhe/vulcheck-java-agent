package cn.bestsec.vulcheck.agent.advice;

import cn.bestsec.vulcheck.spy.Dispatcher;
import cn.bestsec.vulcheck.spy.DispatcherHandler;
import net.bytebuddy.asm.Advice;

import java.lang.reflect.Executable;

/**
 * @author hjx
 * @since 2024/1/2
 * 入口方法增强逻辑
 */
public class EntryAdvice {
    @Advice.OnMethodEnter
    public static void enter(@Advice.Origin Class<?> cls, @Advice.This Object caller, @Advice.Origin Executable exe,
                             @Advice.AllArguments Object[] args) {
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        dispatcher.enterEntry(cls, caller, exe, args);
    }

    @Advice.OnMethodExit
    public static void exit(@Advice.Origin Class<?> cls, @Advice.This Object caller, @Advice.Origin Executable exe,
                            @Advice.AllArguments Object[] args) {
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        dispatcher.exitEntry(cls, caller, exe, args);
    }
}
