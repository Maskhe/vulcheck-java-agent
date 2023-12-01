package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.spy.Dispatcher;
import net.bytebuddy.description.method.MethodDescription;

import java.lang.reflect.Executable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;

/**
 * 分发器实现类
 * @author tntaxin
 * @since 2023/11/20
 */
public class DispatcherImpl implements Dispatcher {
    private final VulCheckContext vulCheckContext = VulCheckContext.newInstance();

    public void handleTaint(String nodeType, Class<?> cls, Object caller, Executable exe, Object args, Object ret) {
        if (!vulCheckContext.isEnterHttp()) {
            return;
        }
        String uniqueMethod = cls.getName() + "." + exe.getName();
        HashMap<String, HookRule> matchedHookPoints = vulCheckContext.getMatchedHookPoints();
        String outParam = matchedHookPoints.get(uniqueMethod).getOut().toLowerCase();
        HashSet<Object> taintPool =  vulCheckContext.getTaintPool().get();

    }
    @Override
    public void enterHttp() {
        vulCheckContext.setEnterHttp(true);
    }

    @Override
    public void exitHttp() {
        vulCheckContext.setEnterHttp(false);
    }

    @Override
    public void enterSource() {
//        System.out.println("进入source节点");;
    }

    @Override
    public void exitSource(Class<?> cls, Object caller, Executable exe, Object[] args, Object ret) {
        if (!vulCheckContext.isEnterHttp()) {
            return;
        }
        String uniqueMethod = cls.getName() + "." + exe.getName();
        HashMap<String, HookRule> matchedHookPoints = vulCheckContext.getMatchedHookPoints();
        String outParam = matchedHookPoints.get(uniqueMethod).getOut().toLowerCase();
        HashSet<Object> taintPool =  vulCheckContext.getTaintPool().get();
        // source节点只把出参放入污点池，出参应该没有或的情况，只有与的情况
        if (outParam.contains("&")) {
            String[] params = outParam.split("&");
            for (String param : params) {
                if (param.equals("o")) {
                    taintPool.add(System.identityHashCode(caller));
                } else if (param.equals("ret") || param.equals("r")) {
                    taintPool.add(System.identityHashCode(ret));
                } else if (param.startsWith("p")) {
                    String paramPosition = param.replace("p", "");
                    for (String position: paramPosition.split(",")) {
                        taintPool.add(System.identityHashCode(args[Integer.parseInt(position)-1]));
                    }
                }
            }
        }
        System.out.println("退出source节点");
    }
    @Override
    public void enterPropagator() {

    }

    @Override
    public void exitPropagator(Class<?> cls, Object caller, Executable exe, Object[] args, Object ret) {
        if (!vulCheckContext.isEnterHttp()) {
            return;
        }
        String clsName = cls.getName();
        String methodName = exe.getName();
        String uniqueMethod = "";
        if (clsName.equals(methodName)){
            uniqueMethod = clsName + ".<init>";
        } else {
            uniqueMethod = cls.getName() + "." + exe.getName();
        }
        HashMap<String, HookRule> matchedHookPoints = vulCheckContext.getMatchedHookPoints();
        String inParam = matchedHookPoints.get(uniqueMethod).getIn();
        String outParam = matchedHookPoints.get(uniqueMethod).getOut();
        ThreadLocal<HashSet<Object>> taintPool =  vulCheckContext.getTaintPool();
        HashSet<Object> set = taintPool.get();
        // 解析入参及出参
        boolean isHitTaintPool = false;
        if (inParam.startsWith("p")){
            inParam = inParam.replace("p", "");
            for (String paramPosition : inParam.split(",")){
                if (set.contains(System.identityHashCode(args[Integer.parseInt(paramPosition)-1]))) {
                    isHitTaintPool = true;
                }
            }
        }else if(inParam.startsWith("o")){
            if (set.contains(System.identityHashCode(caller))) {
                isHitTaintPool = true;
            }
        }

        if (isHitTaintPool) {
            if (outParam.equals("ret")) {
                set.add(System.identityHashCode(ret));
            } else if (outParam.equals("o")) {
                set.add(System.identityHashCode(caller));
            } else if (outParam.startsWith("p")) {
                System.out.println("传播节点出参为p");
            }
        }

    }



    @Override
    public void exitPropagatorWithNoRet(Class<?> cls, Object caller, Executable exe, Object[] args) {
        if (!vulCheckContext.isEnterHttp()) {
            return;
        }
        String clsName = cls.getName();
        String methodName = exe.getName();
        String uniqueMethod = "";
        if (clsName.equals(methodName)){
            uniqueMethod = clsName + ".<init>";
        } else {
            uniqueMethod = cls.getName() + "." + exe.getName();
        }
        HashMap<String, HookRule> matchedHookPoints = vulCheckContext.getMatchedHookPoints();
        String inParam = matchedHookPoints.get(uniqueMethod).getIn();
        String outParam = matchedHookPoints.get(uniqueMethod).getOut();
        ThreadLocal<HashSet<Object>> taintPool =  vulCheckContext.getTaintPool();
        HashSet<Object> set = taintPool.get();
        // 解析入参及出参
        boolean isHitTaintPool = false;
        if (inParam.startsWith("p")){
            inParam = inParam.replace("p", "");
            for (String paramPosition : inParam.split(",")){
                if (set.contains(System.identityHashCode(args[Integer.parseInt(paramPosition)-1]))) {
                    isHitTaintPool = true;
                }
            }
        }else if(inParam.startsWith("o")){
            if (set.contains(System.identityHashCode(caller))) {
                isHitTaintPool = true;
            }
        }

        if (isHitTaintPool) {
            if (outParam.equals("o")) {
                set.add(System.identityHashCode(caller));
            } else if (outParam.startsWith("p")) {
                System.out.println("传播节点出参为p");
            }
        }
    }

    @Override
    public void enterSink(Class<?> cls, Object caller, Executable exe, Object[] args) {
        if (!vulCheckContext.isEnterHttp()) {
            return;
        }
        String uniqueMethod = cls.getName() + "." + exe.getName();
        HashMap<String, HookRule> matchedHookPoints = vulCheckContext.getMatchedHookPoints();
        String inParam = matchedHookPoints.get(uniqueMethod).getIn();
        ThreadLocal<HashSet<Object>> taintPool =  vulCheckContext.getTaintPool();
        HashSet<Object> set = taintPool.get();
        if (inParam.startsWith("p")){
            inParam = inParam.replace("p", "");
            for (String paramPosition : inParam.split(",")){
                if (set.contains(System.identityHashCode(args[Integer.parseInt(paramPosition)-1]))){
                    System.out.println("发现漏洞！");
                }
            }
        }else if(inParam.startsWith("o")){
            if(set.contains(System.identityHashCode(caller))) {
                System.out.println("发现漏洞！");
            }
        }
    }
    @Override
    public void exitSink() {

    }
}
