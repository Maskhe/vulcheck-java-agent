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

    private void parseArgPostion(String inParam, String outParam,Object caller, Object[] args, Object ret, NodeType nodeType, HashSet<Object> taintPool) {
        boolean isHitTaintPool = false;
        if (inParam.isEmpty()) {

        } else if (inParam.startsWith("p")){
            inParam = inParam.replace("p", "");
            for (String paramPosition : inParam.split(",")){
                Object taintValue = args[Integer.parseInt(paramPosition)-1];
                // todo: 其他复合类型检查，例如Map、List类型
                if (taintValue instanceof Object[]) {
                    for (Object taintValueItem : (Object[])taintValue) {
                        System.out.println(taintValueItem);
                        System.out.println(System.identityHashCode(taintValueItem));
                        if (taintPool.contains(System.identityHashCode(taintValueItem))) {
                            isHitTaintPool = true;
                        }
                    }
                } else {
                    if (taintPool.contains(System.identityHashCode(taintValue))) {
                        isHitTaintPool = true;
                    }
                }
            }
        }else if(inParam.startsWith("o")){
            if (taintPool.contains(System.identityHashCode(caller))) {
                isHitTaintPool = true;
            }
        }

        if (nodeType == NodeType.SINK && isHitTaintPool) {
            System.out.println("发现漏洞！");
        }
        if (nodeType == NodeType.SOURCE || (isHitTaintPool && nodeType == NodeType.PROPAGATOR)) {
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
            }
        }
        System.out.println("当前污点池：" + taintPool);
    }
    public void handleTaint(NodeType nodeType, Class<?> cls, Object caller, Executable exe, Object[] args, Object ret) {
        if (!vulCheckContext.isEnterHttp()) {
            return;
        }
        String clsName = cls.getName();
        String methodName = exe.getName();
        String uniqueMethod;
        if (clsName.equals(methodName)){
            uniqueMethod = clsName + ".<init>";
        } else {
            uniqueMethod = cls.getName() + "." + exe.getName();
        }
        System.out.println(uniqueMethod);
        HashMap<String, HookRule> matchedHookPoints = vulCheckContext.getMatchedHookPoints();
        String inParam = matchedHookPoints.get(uniqueMethod).getIn().toLowerCase();
        String outParam = matchedHookPoints.get(uniqueMethod).getOut().toLowerCase();
        HashSet<Object> taintPool =  vulCheckContext.getTaintPool().get();
        parseArgPostion(inParam, outParam, caller, args, ret, nodeType, taintPool);
    }
    @Override
    public void enterHttp() {
        System.out.println("进入http节点");
        vulCheckContext.setEnterHttp(true);
    }

    @Override
    public void exitHttp() {
        System.out.println("退出http节点");
        vulCheckContext.setEnterHttp(false);
    }

    @Override
    public void enterSource() {
//        System.out.println("进入source节点");;
    }

    @Override
    public void exitSource(Class<?> cls, Object caller, Executable exe, Object[] args, Object ret) {
        handleTaint(NodeType.SOURCE, cls, caller, exe, args, ret);
        System.out.println("退出source节点");
    }
    @Override
    public void enterPropagator() {
        System.out.println("进入propagator节点");
    }

    @Override
    public void exitPropagator(Class<?> cls, Object caller, Executable exe, Object[] args, Object ret) {
        // 解析入参及出参
        handleTaint(NodeType.PROPAGATOR, cls, caller, exe, args, ret);
        System.out.println("退出propagator节点");
    }


    @Override
    public void enterPropagatorWithNoRet(Class<?> cls, Object caller, Executable executable, Object[] args) {
        System.out.println("进入propagator节点");
        handleTaint(NodeType.PROPAGATOR, cls, caller, executable, args, null);
    }

    @Override
    public void exitPropagatorWithNoRet(Class<?> cls, Object caller, Executable exe, Object[] args) {
        handleTaint(NodeType.PROPAGATOR, cls, caller, exe, args, null);
        System.out.println("退出propagator节点");
    }

    @Override
    public void enterSink(Class<?> cls, Object caller, Executable exe, Object[] args) {
        System.out.println("进入sink节点-------------------------------------");
        handleTaint(NodeType.SINK, cls, caller, exe, args, null);
    }
    @Override
    public void exitSink() {
        System.out.println("退出sink节点--------------------------------------");
    }
}
