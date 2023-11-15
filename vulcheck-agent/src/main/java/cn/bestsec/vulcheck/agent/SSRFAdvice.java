package cn.bestsec.vulcheck.agent;

import net.bytebuddy.asm.Advice;

import java.lang.reflect.Executable;


public class SSRFAdvice {
    @Advice.OnMethodEnter
    public static void enter(@Advice.Origin Executable executable, @Advice.AllArguments Object[] args) {
        String method = String.valueOf(executable);
        System.out.println("进入：" +method);
    }

    @Advice.OnMethodExit
    public static void exit(@Advice.Origin Executable executable){
        System.out.println("退出：" + executable);

    }
}
