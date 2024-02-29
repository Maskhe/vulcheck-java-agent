package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.agent.enums.NodeType;
import cn.bestsec.vulcheck.spy.Dispatcher;
import net.bytebuddy.description.method.MethodDescription;
import org.tinylog.Logger;

import java.lang.reflect.Executable;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.stream.Collectors;

/**
 * 分发器实现类
 * @author tntaxin
 * @since 2023/11/20
 */
public class DispatcherImpl implements Dispatcher {
    private final VulCheckContext vulCheckContext;

    public DispatcherImpl(VulCheckContext vulCheckContext) {
        this.vulCheckContext = vulCheckContext;
    }

    private void parseArgPostion(String inParam, String outParam,Object caller, Object[] args, Object ret, NodeType nodeType, HashSet<Object> taintPool, String uniqueMethod) {
        vulCheckContext.enterAgent();
        boolean isHitTaintPool = false;
        if (inParam.isEmpty()) {

        } else if (inParam.startsWith("p")){
            inParam = inParam.replace("p", "");
            for (String paramPosition : inParam.split(",")){
                Object taintValue = args[Integer.parseInt(paramPosition)-1];
                // todo: 其他复合类型检查，例如Map、List类型
                if (taintValue instanceof Object[]) {
                    for (Object taintValueItem : (Object[])taintValue) {
                        if (taintPool.contains(System.identityHashCode(taintValueItem))) {
                            if (nodeType == NodeType.SINK) {
                                System.out.println("当前污点值：" + taintValue);
                                System.out.println("当前污点hash：" + System.identityHashCode(taintValue));
                            }
                            isHitTaintPool = true;
                        }
                    }
                }
                if (taintPool.contains(System.identityHashCode(taintValue))) {
                    if (nodeType == NodeType.SINK) {
                        System.out.println("当前污点值：" + taintValue);
                        System.out.println("当前污点hash：" + System.identityHashCode(taintValue));
                    }

                    isHitTaintPool = true;
                }
            }
        }else if(inParam.startsWith("o")){
            if (taintPool.contains(System.identityHashCode(caller))) {
                isHitTaintPool = true;
            }
        }
        if (isHitTaintPool || nodeType == NodeType.SOURCE) {
            System.out.println(uniqueMethod);
        }
        if (nodeType == NodeType.SINK && isHitTaintPool) {
            System.out.println("发现漏洞！");
        }
        if (nodeType == NodeType.SOURCE || (isHitTaintPool && nodeType == NodeType.PROPAGATOR)) {
            // todo:出参如果是复合类型，也需要拆分
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
            } else if (outParam.equals("ret") || outParam.equalsIgnoreCase("r")) {
                taintPool.add(System.identityHashCode(ret));
            } else if (outParam.equalsIgnoreCase("o")) {
                taintPool.add(System.identityHashCode(caller));
            } else if (outParam.startsWith("p")) {
                outParam = outParam.replace("p", "");
                for (String paramPosition : outParam.split(",")){
                    Object taintValue = args[Integer.parseInt(paramPosition)-1];
                    // todo: 其他复合类型检查，例如Map、List类型
                    if (taintValue instanceof Object[]) {
                        for (Object taintValueItem : (Object[])taintValue) {
                            taintPool.add(System.identityHashCode(taintValueItem));
                        }
                    }
                    taintPool.add(System.identityHashCode(taintValue));
                }
            }
        }
//        System.out.println("当前污点池：" + taintPool);
        vulCheckContext.leaveAgent();
    }
    public void handleTaint(String nodeType, Class<?> cls, Object caller, Executable exe, Object[] args, Object ret) {
        if (!vulCheckContext.isEnterEntry() || vulCheckContext.agentDepth > 0) {
            return;
        }
        vulCheckContext.enterAgent();
        System.out.println("a" + "b");
        String clsName = cls.getName();
        String methodName = exe.getName();
        String paramTypes = "";
        paramTypes = Arrays.stream(exe.getParameterTypes()).map(Class::getCanonicalName).collect(Collectors.joining(", "));
        String uniqueMethod;
        if (clsName.equals(methodName)) {
            methodName = "<init>";
        }
        uniqueMethod = String.format("%s.%s(%s)", clsName, methodName, paramTypes);
        Logger.info(uniqueMethod);
        HashMap<String, HookRule> matchedHookPoints = vulCheckContext.getMatchedHookPoints();
        String inParam = matchedHookPoints.get(uniqueMethod).getIn().toLowerCase();
        String outParam = matchedHookPoints.get(uniqueMethod).getOut().toLowerCase();
        HashSet<Object> taintPool =  vulCheckContext.getTaintPool().get();
        parseArgPostion(inParam, outParam, caller, args, ret, NodeType.getByName(nodeType), taintPool, uniqueMethod);
        vulCheckContext.leaveAgent();
    }
    @Override
    public void enterEntry() {
        Logger.debug("进入entry节点");
        vulCheckContext.setEnterEntry(true);
    }

    @Override
    public void exitEntry() {
        vulCheckContext.setEnterEntry(false);
        Logger.debug("推出entry节点");
    }

    @Override
    public void enterSource() {
        vulCheckContext.sourceDepth ++;
    }

    @Override
    public void exitSource(Class<?> cls, Object caller, Executable exe, Object[] args, Object ret) {
        if (!vulCheckContext.isValidSource()) {
            vulCheckContext.sourceDepth --;
            return;
        }
        vulCheckContext.sourceDepth --;
        handleTaint("source", cls, caller, exe, args, ret);
    }
    @Override
    public void enterPropagator() {
        vulCheckContext.propagatorDepth ++;
    }

    @Override
    public void exitPropagator(Class<?> cls, Object caller, Executable exe, Object[] args, Object ret) {
//        if (!vulCheckContext.isValidPropagator() || vulCheckContext.getTaintPool().get().isEmpty()) {
//            vulCheckContext.propagatorDepth --;
//            return;
//        }
        vulCheckContext.propagatorDepth --;
        handleTaint("propagator", cls, caller, exe, args, ret);
    }


    @Override
    public void enterPropagatorWithNoRet(Class<?> cls, Object caller, Executable executable, Object[] args) {
        vulCheckContext.propagatorDepth ++;
    }

    @Override
    public void enterPropagatorWithoutThis(Object[] args) {
//        System.out.println("123");
    }

    @Override
    public void exitPropagatorWithNoRet(Class<?> cls, Object caller, Executable exe, Object[] args) {
        if (!vulCheckContext.isValidPropagator()) {
            vulCheckContext.propagatorDepth --;
            return;
        }
        vulCheckContext.propagatorDepth --;
        handleTaint("propagator", cls, caller, exe, args, null);
    }

    @Override
    public void enterSink(Class<?> cls, Object caller, Executable exe, Object[] args) {
//        vulCheckContext.sinkDepth ++;
//        if (!vulCheckContext.isValidSink()){
//            return;
//        }
        System.out.println("进入sink节点-------------------------------------");
        handleTaint("sink", cls, caller, exe, args, null);
    }
    @Override
    public void exitSink() {
        if (!vulCheckContext.isValidSink()){
            vulCheckContext.sinkDepth --;
            return;
        }
        vulCheckContext.sinkDepth --;
        System.out.println("退出sink节点--------------------------------------");
    }

    @Override
    public void enterAgent() {
        vulCheckContext.agentDepth++;
    }

    @Override
    public void leaveAgent() {
        vulCheckContext.agentDepth--;
    }

    @Override
    public boolean isEnterAgent() {
        return vulCheckContext.agentDepth > 0;
    }

    @Override
    public void test() {
        System.out.println("tre");
    }
}
