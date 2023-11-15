package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.spy.HookRule;
import net.bytebuddy.asm.Advice;

import java.lang.reflect.Executable;
import java.util.HashMap;
import java.util.HashSet;
import cn.bestsec.vulcheck.spy.VulCheckContext;

public class SinkAdvice {
    @Advice.OnMethodEnter
    public static void enter(@Advice.Origin Class<?> cls, @Advice.Origin Executable exe, @Advice.AllArguments Object[] args, @Advice.Origin("#m") String methodName,
                             @Advice.Origin("#t") Class<?> declaringType,
                             @Advice.Origin("#t") String simpleTypeName){
        System.out.println("进入sink节点");
        String uniqueMethod = cls.getName() + "." + exe.getName();
        VulCheckContext vulCheckContext = VulCheckContext.newInstance();
        HashMap<String, HookRule> hookRules = vulCheckContext.getHookRules();
        String inParam = hookRules.get(uniqueMethod).getIn();
        ThreadLocal<HashSet<Object>> taintPool =  vulCheckContext.getTaintPool();
        HashSet<Object> set = taintPool.get();
        if (inParam.startsWith("p")){
            inParam = inParam.replace("p", "");
            for (String param : inParam.split(",")){
                if (set.contains(args[Integer.parseInt(param) - 1])){
                    System.out.println("发现漏洞！");
                }
            }
        }else if(inParam.startsWith("o")){
//            System.out.println(caller);
        }

    }

    @Advice.OnMethodExit
    public static void exit(){
        System.out.println("退出sink节点");
    }
}
