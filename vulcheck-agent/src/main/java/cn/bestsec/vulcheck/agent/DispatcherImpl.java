package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.agent.enums.NodeTypeEnum;
import cn.bestsec.vulcheck.agent.enums.PositionTypeEnum;
import cn.bestsec.vulcheck.agent.trace.MethodEvent;
import cn.bestsec.vulcheck.agent.trace.Taint;
import cn.bestsec.vulcheck.agent.trace.TracingContextManager;
import cn.bestsec.vulcheck.spy.Dispatcher;
import org.tinylog.Logger;

import java.lang.reflect.Executable;
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

    private Object getTaintByPosition(TaintPosition position, Object caller, Object[] args, Object ret) {
        Object taintValue;
        switch (position.getPositionType()) {
            case PARAM:
                taintValue = args[position.getIndex() - 1];
                break;
            case CALLER:
                taintValue = caller;
                break;
            case RET:
                taintValue = ret;
                break;
            default:
                taintValue = null;
                break;
        }
        return taintValue;
    }
    private void captureMethodState(TaintPositions sources, TaintPositions targets, Object caller, Object[] args, Object ret, NodeTypeEnum nodeType, HashSet<Object> taintPool,String uniqueMethod) {
        boolean isHitTaintPool = false;
        ArrayList<Taint> sourceTaints = new ArrayList<>();
        if (sources != null) {
            for (TaintPosition taintPosition : sources.getPositions()) {
                Object taintValue = getTaintByPosition(taintPosition, caller, args, ret);
                Logger.debug(taintValue);
                int taintHash = System.identityHashCode(taintValue);
                if (taintPool.contains(taintHash)) {
                    sourceTaints.add(new Taint(taintValue, taintHash));
                }
            }
            if (sources.getRelation().equals("AND")) {
                isHitTaintPool = sources.getPositions().size() == sourceTaints.size();
            } else {
                isHitTaintPool = !sourceTaints.isEmpty();
            }
        }

        ArrayList<Taint> targetTaints = new ArrayList<>();
        MethodEvent methodEvent = new MethodEvent();
        switch (nodeType) {
            case SOURCE:
                for (TaintPosition taintPosition : targets.getPositions()) {
                    Object taintValue = getTaintByPosition(taintPosition, caller, args, ret);
                    int taintHash = System.identityHashCode(taintValue);
                    taintPool.add(taintHash);
                    targetTaints.add(new Taint(taintValue, taintHash));
                }
                break;
            case PROPAGATOR:
            case SANITIZER:
                if (isHitTaintPool) {
                    // todo: 类似于集合这种复合数据类型需要拆分后再加入污点池中吗
                    for (TaintPosition taintPosition : targets.getPositions()) {
                        Object taintValue = getTaintByPosition(taintPosition, caller, args, ret);
                        Logger.debug(taintValue);
                        int taintHash = System.identityHashCode(taintValue);
                        taintPool.add(taintHash);
                        targetTaints.add(new Taint(taintValue, taintHash));
                    }
                }
                break;
            case SINK:
                if (isHitTaintPool) {
                    Logger.info("发现漏洞！");
                }
                break;
        }
        methodEvent.setSourceTaints(sourceTaints);
        methodEvent.setTargetTaints(targetTaints);
        TracingContextManager.getContext().addMethodToSegment(methodEvent);
    }
//    private void parseArgPostion(TaintPositions sources, TaintPositions targets, Object caller, Object[] args, Object ret, NodeTypeEnum nodeType, HashSet<Object> taintPool, String uniqueMethod) {
//        boolean isHitTaintPool = false;
//        if (sources == null) {
//
//        } else if (inParam.startsWith("p")){
//            inParam = inParam.replace("p", "");
//            for (String paramPosition : inParam.split(",")){
//                Object taintValue = args[Integer.parseInt(paramPosition)-1];
//                // todo: 其他复合类型检查，例如Map、List类型
//                if (taintValue instanceof Object[]) {
//                    for (Object taintValueItem : (Object[])taintValue) {
//                        if (taintPool.contains(System.identityHashCode(taintValueItem))) {
//                            if (nodeType == NodeTypeEnum.SINK) {
//                                System.out.println("当前污点值：" + taintValue);
//                                System.out.println("当前污点hash：" + System.identityHashCode(taintValue));
//                            }
//                            isHitTaintPool = true;
//                        }
//                    }
//                }
//                if (taintPool.contains(System.identityHashCode(taintValue))) {
//                    if (nodeType == NodeTypeEnum.SINK) {
//                        System.out.println("当前污点值：" + taintValue);
//                        System.out.println("当前污点hash：" + System.identityHashCode(taintValue));
//                    }
//
//                    isHitTaintPool = true;
//                }
//            }
//        }else if(inParam.startsWith("o")){
//            if (taintPool.contains(System.identityHashCode(caller))) {
//                isHitTaintPool = true;
//            }
//        }
//        if (isHitTaintPool || nodeType == NodeTypeEnum.SOURCE) {
//            System.out.println(uniqueMethod);
//        }
//        if (nodeType == NodeTypeEnum.SINK && isHitTaintPool) {
//            System.out.println("发现漏洞！");
//        }
//        if (nodeType == NodeTypeEnum.SOURCE || (isHitTaintPool && nodeType == NodeTypeEnum.PROPAGATOR)) {
//            // todo:出参如果是复合类型，也需要拆分
//            if (outParam.contains("&")) {
//                String[] params = outParam.split("&");
//                for (String param : params) {
//                    if (param.equals("o")) {
//                        taintPool.add(System.identityHashCode(caller));
//                    } else if (param.equals("ret") || param.equals("r")) {
//                        taintPool.add(System.identityHashCode(ret));
//                    } else if (param.startsWith("p")) {
//                        String paramPosition = param.replace("p", "");
//                        for (String position: paramPosition.split(",")) {
//                            taintPool.add(System.identityHashCode(args[Integer.parseInt(position)-1]));
//                        }
//                    }
//                }
//            } else if (outParam.equals("ret") || outParam.equalsIgnoreCase("r")) {
//                taintPool.add(System.identityHashCode(ret));
//            } else if (outParam.equalsIgnoreCase("o")) {
//                taintPool.add(System.identityHashCode(caller));
//            } else if (outParam.startsWith("p")) {
//                outParam = outParam.replace("p", "");
//                for (String paramPosition : outParam.split(",")){
//                    Object taintValue = args[Integer.parseInt(paramPosition)-1];
//                    // todo: 其他复合类型检查，例如Map、List类型
//                    if (taintValue instanceof Object[]) {
//                        for (Object taintValueItem : (Object[])taintValue) {
//                            taintPool.add(System.identityHashCode(taintValueItem));
//                        }
//                    }
//                    taintPool.add(System.identityHashCode(taintValue));
//                }
//            }
//        }
//    }
    public void trackMethodCall(NodeTypeEnum nodeType, Class<?> cls, Object caller, Executable exe, Object[] args, Object ret) {
        System.out.println(vulCheckContext.agentDepth.get());
        if (vulCheckContext.isEnterAgent()) {
            return;
        }
        vulCheckContext.enterAgent();
        String clsName = cls.getName();
        String methodName = exe.getName();
        String paramTypes = Arrays.stream(exe.getParameterTypes()).map(Class::getCanonicalName).collect(Collectors.joining(", "));
        String uniqueMethod;
        if (clsName.equals(methodName)) {
            methodName = "<init>";
        }
        uniqueMethod = String.format("%s.%s(%s)", clsName, methodName, paramTypes);
        Logger.info("trackMethodCall: " + uniqueMethod);
        HashMap<String, HookRule> matchedHookNodes = vulCheckContext.getMatchedHookNodes();
        // todo: 污点入参的处理逻辑需要大更改
        if (matchedHookNodes.get(uniqueMethod) == null) {
            // 当前方法非预设得hook方法
            return;
        }
        TaintPositions sources = matchedHookNodes.get(uniqueMethod).getTaintSources();
        TaintPositions targets = matchedHookNodes.get(uniqueMethod).getTaintTargets();
        HashSet<Object> taintPool = vulCheckContext.getTaintPool().get();
        captureMethodState(sources, targets, caller, args, ret, nodeType, taintPool, uniqueMethod);
        vulCheckContext.leaveAgent();
    }
    @Override
    public void enterEntry() {
        Logger.debug("进入entry节点");
        vulCheckContext.setEnterEntry(true);
        vulCheckContext.getTaintPool().set(new HashSet<>());
        vulCheckContext.getAgentDepth().set(0);
    }

    @Override
    public void exitEntry() {
        vulCheckContext.setEnterEntry(false);
        Logger.debug("退出entry节点");
    }

    @Override
    public void enterSource() {
        Logger.debug("进入source节点");
        vulCheckContext.sourceDepth ++;
    }

    @Override
    public void exitSource(Class<?> cls, Object caller, Executable exe, Object[] args, Object ret) {
        if (!vulCheckContext.isValidSource()) {
            vulCheckContext.sourceDepth --;
            Logger.debug("嵌套source节点，不执行污点捕获，直接退出");
            return;
        }
        vulCheckContext.sourceDepth --;
        trackMethodCall(NodeTypeEnum.SOURCE, cls, caller, exe, args, ret);
        Logger.debug("退出source节点");
    }
    @Override
    public void enterPropagator() {
        vulCheckContext.propagatorDepth.incrementAndGet();
    }

    @Override
    public void exitPropagator(Class<?> cls, Object caller, Executable exe, Object[] args, Object ret) {
        if (!vulCheckContext.isValidPropagator() || vulCheckContext.getTaintPool().get().isEmpty()) {
            vulCheckContext.propagatorDepth.decrementAndGet();
            return;
        }
        vulCheckContext.propagatorDepth.decrementAndGet();
        trackMethodCall(NodeTypeEnum.PROPAGATOR, cls, caller, exe, args, ret);
    }


    @Override
    public void enterPropagatorWithNoRet(Class<?> cls, Object caller, Executable executable, Object[] args) {
        vulCheckContext.propagatorDepth.incrementAndGet();
    }

    @Override
    public void enterPropagatorWithoutThis(Object[] args) {
//        System.out.println(111111111);
//        System.out.println("123");
    }

    @Override
    public void exitPropagatorWithNoRet(Class<?> cls, Object caller, Executable exe, Object[] args) {
        if (!vulCheckContext.isValidPropagator()) {
            vulCheckContext.propagatorDepth.decrementAndGet();
            return;
        }
        vulCheckContext.propagatorDepth.decrementAndGet();
        trackMethodCall(NodeTypeEnum.PROPAGATOR, cls, caller, exe, args, null);
    }

    @Override
    public void enterSink(Class<?> cls, Object caller, Executable exe, Object[] args) {
        vulCheckContext.sinkDepth ++;
        if (!vulCheckContext.isValidSink()){
            return;
        }
        Logger.debug("进入sink节点");
        trackMethodCall(NodeTypeEnum.SINK, cls, caller, exe, args, null);
    }
    @Override
    public void exitSink() {
        if (!vulCheckContext.isValidSink()){
            vulCheckContext.sinkDepth --;
            return;
        }
        vulCheckContext.sinkDepth --;
        Logger.debug("退出sink节点");
    }

    @Override
    public void enterAgent() {
        vulCheckContext.agentDepth.set(vulCheckContext.agentDepth.get() + 1);
//        vulCheckContext.agentDepth.incrementAndGet();
    }

    @Override
    public void leaveAgent() {
        vulCheckContext.agentDepth.set(vulCheckContext.agentDepth.get() - 1);
//        vulCheckContext.agentDepth.decrementAndGet();
    }

    @Override
    public boolean isEnterAgent() {
        return vulCheckContext.agentDepth.get() > 0;
    }

    @Override
    public void test() {
        System.out.println("tre");
    }
}
