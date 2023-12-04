package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.agent.enums.NodeType;
import cn.bestsec.vulcheck.spy.Dispatcher;
import net.bytebuddy.description.method.MethodDescription;

import javax.xml.soap.Node;
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

    private void parseArgPostion(String inParam, String outParam,Object caller, Object[] args, Object ret, NodeType nodeType, HashSet<Object> taintPool) {
        boolean isHitTaintPool = false;
        if (inParam.isEmpty()) {

        } else if (inParam.startsWith("p")){
            inParam = inParam.replace("p", "");
            for (String paramPosition : inParam.split(",")){
                if (taintPool.contains(System.identityHashCode(args[Integer.parseInt(paramPosition)-1]))) {
                    isHitTaintPool = true;
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

        if (nodeType == NodeType.SOURCE || isHitTaintPool) {
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
        }
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
        HashMap<String, HookRule> matchedHookPoints = vulCheckContext.getMatchedHookPoints();
        String inParam = matchedHookPoints.get(uniqueMethod).getIn().toLowerCase();
        String outParam = matchedHookPoints.get(uniqueMethod).getOut().toLowerCase();
        HashSet<Object> taintPool =  vulCheckContext.getTaintPool().get();
        parseArgPostion(inParam, outParam, caller, args, ret, nodeType, taintPool);
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
        handleTaint(NodeType.SOURCE, cls, caller, exe, args, ret);
        System.out.println("退出source节点");
    }
    @Override
    public void enterPropagator() {

    }

    @Override
    public void exitPropagator(Class<?> cls, Object caller, Executable exe, Object[] args, Object ret) {
        // 解析入参及出参
        handleTaint(NodeType.PROPAGATOR, cls, caller, exe, args, ret);
    }



    @Override
    public void exitPropagatorWithNoRet(Class<?> cls, Object caller, Executable exe, Object[] args) {
        handleTaint(NodeType.PROPAGATOR, cls, caller, exe, args, null);
    }

    @Override
    public void enterSink(Class<?> cls, Object caller, Executable exe, Object[] args) {
        handleTaint(NodeType.SINK, cls, caller, exe, args, null);
    }
    @Override
    public void exitSink() {

    }
}
