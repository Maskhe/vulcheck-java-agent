package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.spy.HookRule;
import cn.bestsec.vulcheck.spy.VulCheckContext;
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
        String uniqueMethod = cls.getName() + "." + exe.getName();
        VulCheckContext vulCheckContext = VulCheckContext.newInstance();
        HashMap<String, HookRule> hookRules = vulCheckContext.getHookRules();
        String inParam = hookRules.get(uniqueMethod).getIn();
        String outParam = hookRules.get(uniqueMethod).getOut();
        ThreadLocal<HashSet<Object>> taintPool =  vulCheckContext.getTaintPool();
        HashSet<Object> set = taintPool.get();
        if (inParam.startsWith("p")){
            inParam = inParam.replace("p", "");
            for (String param : inParam.split(",")){
                set.add(args[Integer.parseInt(param)-1]);
            }
        }else if(inParam.startsWith("o")){
//            System.out.println(caller);
        }
        if (outParam.equals("ret")) {
            set.add(ret);
//            log.info("当前污点池" + set);
        }
        System.out.println("退出source节点");
    }

}
