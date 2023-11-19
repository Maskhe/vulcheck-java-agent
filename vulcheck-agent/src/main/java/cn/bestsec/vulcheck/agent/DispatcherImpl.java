package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.spy.Dispatcher;
import net.bytebuddy.description.method.MethodDescription;

import java.lang.reflect.Executable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

public class DispatcherImpl implements Dispatcher {

    @Override
    public void enterSource() {
        System.out.println("进入source节点");;
    }

    @Override
    public void enterPropagator() {

    }

    @Override
    public void enterSink(Class<?> cls, Executable exe, Object[] args, Object o) {
//        System.out.println("进入sink节点");
        String uniqueMethod = cls.getName() + "." + exe.getName();
        VulCheckContext vulCheckContext = VulCheckContext.newInstance();
        HashMap<String, HookRule> matchedHookPoints = vulCheckContext.getMatchedHookPoints();
        String inParam = matchedHookPoints.get(uniqueMethod).getIn();
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
//            if()
//            System.out.println(caller);
//            System.out.println(set);
//            System.out.println();
        }
    }

    @Override
    public void exitSource(Class<?> cls, Executable exe, Object[] args, String ret) {
        String uniqueMethod = cls.getName() + "." + exe.getName();
        VulCheckContext vulCheckContext = VulCheckContext.newInstance();
        HashMap<String, HookRule> matchedHookPoints = vulCheckContext.getMatchedHookPoints();
        String inParam = matchedHookPoints.get(uniqueMethod).getIn();
        String outParam = matchedHookPoints.get(uniqueMethod).getOut();
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

    @Override
    public void exitPropagator(Class<?> cls, Executable exe, Object[] args, Object ret) {
        String clsName = cls.getName();
        String methodName = exe.getName();
        String uniqueMethod = "";
        if (clsName.equals(methodName)){
            uniqueMethod = clsName + ".<init>";
        } else {
            uniqueMethod = cls.getName() + "." + exe.getName();
        }
        VulCheckContext vulCheckContext = VulCheckContext.newInstance();
        HashMap<String, HookRule> matchedHookPoints = vulCheckContext.getMatchedHookPoints();
//        System.out.println(uniqueMethod);
//        System.out.println(matchedHookPoints);
        String inParam = matchedHookPoints.get(uniqueMethod).getIn();
        String outParam = matchedHookPoints.get(uniqueMethod).getOut();
//        System.out.println(inParam);
//        System.out.println(outParam);
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
        }
//        System.out.println("退出propagator节点");
    }

    @Override
    public void exitSink() {

    }
}
