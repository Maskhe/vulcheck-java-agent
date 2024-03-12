package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.agent.enums.NodeTypeEnum;
import cn.bestsec.vulcheck.agent.enums.PositionTypeEnum;
import cn.bestsec.vulcheck.agent.trace.MethodEvent;
import cn.bestsec.vulcheck.agent.trace.Taint;
import cn.bestsec.vulcheck.agent.trace.TracingContext;
import cn.bestsec.vulcheck.agent.trace.TracingContextManager;
import cn.bestsec.vulcheck.agent.utils.HookRuleUtils;
import cn.bestsec.vulcheck.spy.Dispatcher;
import cn.bestsec.vulcheck.spy.OriginCaller;
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
    private final TracingContext tracingContext;

    public DispatcherImpl(VulCheckContext vulCheckContext) {
        this.vulCheckContext = vulCheckContext;
        this.tracingContext = TracingContextManager.getContext();
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
    private void captureMethodState(TaintPositions sources, TaintPositions targets, Object caller, Object[] args, Object ret, NodeTypeEnum nodeType, HashSet<Object> taintPool, OriginCaller originCaller) {
        boolean isHitTaintPool = false;
        ArrayList<Taint> sourceTaints = new ArrayList<>();

        if (sources != null) {
            for (TaintPosition taintPosition : sources.getPositions()) {
                Object taintValue = getTaintByPosition(taintPosition, caller, args, ret);
                int taintHash;
                if (taintPosition.getPositionType().equals(PositionTypeEnum.CALLER) && nodeType.equals(NodeTypeEnum.PROPAGATOR)) {
                    // 传播节点的caller对象的hash在onmethodenter阶段生成
                    taintHash = originCaller.callerHash;
                } else {
//                    taintHash = System.identityHashCode(taintValue);
                    taintHash = taintValue.hashCode();
                }
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
                    int taintHash = taintValue.hashCode();
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
                        Logger.debug("当前污点值：" + taintValue);
//                        int taintHash = System.identityHashCode(taintValue);
                        int taintHash = taintValue.hashCode();
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
    public void trackMethodCall(NodeTypeEnum nodeType, Class<?> cls, Object caller, Executable exe, Object[] args,
                                Object ret, OriginCaller originCaller) {
        if (this.tracingContext.isEnterAgent()) {
            return;
        }
        this.tracingContext.enterAgent();
        HookRule currentHookRule = HookRuleUtils.getHookRule(cls, exe);
//        Logger.info(currentHookRule);
        if (currentHookRule == null) {
            return;
        }
        TaintPositions sources = currentHookRule.getTaintSources();
        TaintPositions targets = currentHookRule.getTaintTargets();
        HashSet<Object> taintPool = vulCheckContext.getTaintPool().get();
        captureMethodState(sources, targets, caller, args, ret, nodeType, taintPool, originCaller);
        this.tracingContext.exitAgent();
    }
    @Override
    public void enterEntry() {
        this.tracingContext.enterEntry();
//        vulCheckContext.entryDepth.incrementAndGet();
        vulCheckContext.getTaintPool().set(new HashSet<>());
        this.tracingContext.enterEntry();
//        vulCheckContext.getAgentDepth().set(0);
    }

    @Override
    public void exitEntry() {
//        vulCheckContext.entryDepth.decrementAndGet();
        this.tracingContext.exitEntry();
    }

    @Override
    public void enterSource() {
        Logger.debug("进入source节点");
//        vulCheckContext.sourceDepth ++;
        this.tracingContext.enterSource();
    }

    @Override
    public void exitSource(Class<?> cls, Object caller, Executable exe, Object[] args, Object ret) {
        if (!this.tracingContext.isValidSource()) {
//            vulCheckContext.sourceDepth --;
            this.tracingContext.exitSource();
            return;
        }
        System.out.println(this.tracingContext.getSourceDepth());
        System.out.println(this.tracingContext.isEnterEntry());
        System.out.println(this.tracingContext.getPropagatorDepth());
        System.out.println(this.tracingContext.isEnterAgent());
        trackMethodCall(NodeTypeEnum.SOURCE, cls, caller, exe, args, ret, null);
        Logger.debug("退出source节点");
        this.tracingContext.exitSource();
    }
    @Override
    public OriginCaller enterPropagator(Class<?> cls, Object caller, Executable executable, Object[] args) {
//        vulCheckContext.propagatorDepth.incrementAndGet();
        this.tracingContext.enterPropagator();
        OriginCaller originalCaller = new OriginCaller();
        int callerHash = 0;
        HookRule currentHookRule = null;
        if (this.tracingContext.isValidPropagator() && !vulCheckContext.getTaintPool().get().isEmpty()) {
            this.tracingContext.enterAgent();
            currentHookRule = HookRuleUtils.getHookRule(cls, executable);
            if (currentHookRule.getIn().contains("O")) {
                callerHash = caller.hashCode();
            }
            this.tracingContext.exitAgent();
        }
        originalCaller.callerHash = callerHash;
        originalCaller.hookRule = currentHookRule;
        return originalCaller;
    }

    @Override
    public void exitPropagator(Class<?> cls, Object caller, Executable exe, Object[] args, Object ret, OriginCaller originalCaller) {
        if (vulCheckContext.getTaintPool().get().isEmpty()) {
            this.tracingContext.exitPropagator();
            return;
        }
        // fix: 在退出的时候捕获caller会有问题，因为此时的caller已经是被当前方法修改过后的caller了，例如对于StringBuilder.append(java.lang.String)方法，
        if (!this.tracingContext.isValidPropagator()) {
            System.out.println(this.tracingContext.getPropagatorDepth());
            this.tracingContext.exitPropagator();
            return;
        }
        trackMethodCall(NodeTypeEnum.PROPAGATOR, cls, caller, exe, args, ret, originalCaller);
        this.tracingContext.exitPropagator();
    }

    @Override
    public void exitPropagatorWithoutThis(Class<?> cls, Executable executable, Object[] args, Object ret) {
        if (!this.tracingContext.isValidPropagator() || vulCheckContext.getTaintPool().get().isEmpty()) {
            this.tracingContext.exitPropagator();
            return;
        }
        trackMethodCall(NodeTypeEnum.PROPAGATOR, cls, null, executable, args, ret, null);
        this.tracingContext.exitPropagator();
    }


    @Override
    public void enterPropagatorWithNoRet(Class<?> cls, Object caller, Executable executable, Object[] args) {
        vulCheckContext.propagatorDepth.incrementAndGet();
    }

    @Override
    public void enterPropagatorWithoutThis() {
        this.tracingContext.enterPropagator();
    }

    @Override
    public void enterConstructorPropagator() {
        this.tracingContext.enterPropagator();
    }

    @Override
    public void exitConstructorPropagator(Class<?> cls, Object caller, Executable executable, Object[] args, Object ret) {
        if (!this.tracingContext.isValidPropagator() || vulCheckContext.getTaintPool().get().isEmpty()) {
            this.tracingContext.exitPropagator();
            return;
        }
        trackMethodCall(NodeTypeEnum.PROPAGATOR, cls, caller, executable, args, ret, null);
        this.tracingContext.exitPropagator();
    }


    @Override
    public void exitPropagatorWithNoRet(Class<?> cls, Object caller, Executable exe, Object[] args) {
        if (!vulCheckContext.isValidPropagator()) {
            vulCheckContext.propagatorDepth.decrementAndGet();
            return;
        }
        trackMethodCall(NodeTypeEnum.PROPAGATOR, cls, caller, exe, args, null, null);
        vulCheckContext.propagatorDepth.decrementAndGet();
    }

    @Override
    public void enterSink(Class<?> cls, Object caller, Executable exe, Object[] args) {
        this.tracingContext.enterSink();
        if (!this.tracingContext.isValidSink()){
            return;
        }
        trackMethodCall(NodeTypeEnum.SINK, cls, caller, exe, args, null, null);
    }
    @Override
    public void exitSink() {
        this.tracingContext.exitSink();
    }

    @Override
    public void enterAgent() {
        vulCheckContext.agentDepth.set(vulCheckContext.agentDepth.get() + 1);
    }

    @Override
    public void leaveAgent() {
        vulCheckContext.agentDepth.set(vulCheckContext.agentDepth.get() - 1);
    }

    @Override
    public boolean isEnterAgent() {
        return vulCheckContext.agentDepth.get() > 0;
    }
}
