package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.agent.enums.NodeType;
import cn.bestsec.vulcheck.spy.Dispatcher;
import net.bytebuddy.description.method.MethodDescription;

//import javax.xml.soap.Node;
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
        if (!vulCheckContext.isEnterHttp() || vulCheckContext.agentDepth > 0) {
            return;
        }
        vulCheckContext.enterAgent();
        String clsName = cls.getName();
        String methodName = exe.getName();
        String uniqueMethod;
        if (clsName.equals(methodName)){
            uniqueMethod = clsName + ".<init>";
        } else {
            uniqueMethod = cls.getName() + "." + exe.getName();
        }

        HashMap<String, HookRule> matchedHookPoints = vulCheckContext.getMatchedHookPoints();
        String inParam = matchedHookPoints.get(uniqueMethod).getIn().toLowerCase();
        String outParam = matchedHookPoints.get(uniqueMethod).getOut().toLowerCase();
        HashSet<Object> taintPool =  vulCheckContext.getTaintPool().get();
        parseArgPostion(inParam, outParam, caller, args, ret, NodeType.getByName(nodeType), taintPool, uniqueMethod);
        vulCheckContext.leaveAgent();
    }
    @Override
    public void enterHttp() {
//        System.out.println("进入http节点");
        vulCheckContext.setEnterHttp(true);
    }

    @Override
    public void exitHttp() {
//        System.out.println("退出http节点");
        vulCheckContext.setEnterHttp(false);
    }

    @Override
    public void enterSource() {
//        System.out.println("进入source节点");
    }

    @Override
    public void exitSource(Class<?> cls, Object caller, Executable exe, Object[] args, Object ret) {
        handleTaint("source", cls, caller, exe, args, ret);
        System.out.println("退出source节点");
    }
    @Override
    public void enterPropagator() {
//        System.out.println("进入propagator节点");
    }

    @Override
    public void exitPropagator(Class<?> cls, Object caller, Executable exe, Object[] args, Object ret) {
        // 解析入参及出参
        handleTaint("propagator", cls, caller, exe, args, ret);
//        System.out.println("退出propagator节点");
    }


    @Override
    public void enterPropagatorWithNoRet(Class<?> cls, Object caller, Executable executable, Object[] args) {
//        System.out.println("进入propagator节点");
        handleTaint("propagator", cls, caller, executable, args, null);
    }

    @Override
    public void exitPropagatorWithNoRet(Class<?> cls, Object caller, Executable exe, Object[] args) {
//        System.out.println(NodeType.PROPAGATOR);
//        test();
        handleTaint("propagator", cls, caller, exe, args, null);
//        System.out.println("退出propagator节点");
    }

    @Override
    public void enterSink(Class<?> cls, Object caller, Executable exe, Object[] args) {
//        System.out.println("进入sink节点-------------------------------------");
        handleTaint("sink", cls, caller, exe, args, null);
    }
    @Override
    public void exitSink() {
//        System.out.println("退出sink节点--------------------------------------");
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
