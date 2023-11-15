package cn.bestsec.vulcheck.agent;

import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import java.lang.reflect.Executable;

public class PropagatorAdvice {
    @Advice.OnMethodEnter
    public static void enter(){
        System.out.println("进入propagator节点");
    }

    @Advice.OnMethodExit
    public static void exit(@Advice.Origin Class<?> cls, @Advice.Origin Executable exe, @Advice.AllArguments Object[] args, @Advice.Origin("#m") String methodName,
                            @Advice.Origin("#t") Class<?> declaringType,
                            @Advice.Origin("#t") String simpleTypeName, @Advice.Return(typing = Assigner.Typing.DYNAMIC) Object ret){
//        String uniqueMethod = cls.getName() + "." + exe.getName();
//        VulCheckContext vulCheckContext = VulCheckContext.newInstance();
//        HashMap<String, HookRule> hookRules = vulCheckContext.getHookRules();
//        String inParam = hookRules.get(uniqueMethod).getIn();
//        String outParam = hookRules.get(uniqueMethod).getOut();
//        ThreadLocal<HashSet<Object>> taintPool =  vulCheckContext.getTaintPool();
//        HashSet<Object> set = taintPool.get();
//        if (inParam.startsWith("p")){
//            inParam = inParam.replace("p", "");
//            for (String param : inParam.split(",")){
//
//                set.add(args[Integer.parseInt(param)-1]);
//            }
//        }else if(inParam.startsWith("o")){
////            System.out.println(caller);
//        }
//        if (outParam.equals("ret")) {
//            set.add(ret);
//        }
//        System.out.println("退出propagator节点");
    }
}
