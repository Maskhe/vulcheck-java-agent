package cn.bestsec.vulcheck.agent.advice;

import net.bytebuddy.asm.Advice;

import java.lang.reflect.Field;

public class AllFieldsAccessAdvice {
    @Advice.OnMethodEnter
    static void enter(@Advice.Origin Field field) {
        // 在进入方法时执行，输出字段名和类型
        System.out.println("Accessing Field: " + field.getName() + ", Type: " + field.getType());
    }
}
