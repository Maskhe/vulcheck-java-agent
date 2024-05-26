package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.agent.enums.NodeTypeEnum;
import cn.bestsec.vulcheck.agent.enums.PositionTypeEnum;
import cn.bestsec.vulcheck.agent.rule.HookRule;
import cn.bestsec.vulcheck.agent.rule.TaintPosition;
import cn.bestsec.vulcheck.agent.rule.TaintPositions;
import cn.bestsec.vulcheck.agent.trace.MethodEvent;
import cn.bestsec.vulcheck.agent.trace.Taint;
import cn.bestsec.vulcheck.agent.trace.TracingContext;
import cn.bestsec.vulcheck.agent.trace.http.HttpRequest;
import cn.bestsec.vulcheck.agent.trace.http.HttpResponse;
import cn.bestsec.vulcheck.agent.utils.HashUtils;
import cn.bestsec.vulcheck.agent.utils.HookRuleUtils;
import cn.bestsec.vulcheck.agent.utils.ReflectionUtils;
import cn.bestsec.vulcheck.spy.Dispatcher;
import cn.bestsec.vulcheck.spy.OriginCaller;
import org.tinylog.Logger;

import java.io.*;
import java.lang.reflect.Executable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * 分发器实现类
 * @author tntaxin
 * @since 2023/11/20
 */
public class DispatcherImpl implements Dispatcher {
    private final VulCheckContext vulCheckContext;
    private TracingContext tracingContext;

    public DispatcherImpl(VulCheckContext vulCheckContext) {
        this.vulCheckContext = vulCheckContext;
        this.tracingContext = this.vulCheckContext.getTracingContextManager().getContext();
    }

    /**
     * 根据位置获取污点对象
     * @param position 污点位置
     * @param caller 被插桩方法的this对象
     * @param args 被插桩方法的参数
     * @param ret 被插桩方法的返回值
     * @return 污点对象
     */
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

    /**
     * 判断当前对象是否命中污点池，对于简单数据类型
     * @param obj 待判断的对象
     * @param sourceTaints 如果obj命中污点池将被存储到这个List对象中
     * @return True | False
     */
    private boolean isHitTaintPool(Object obj, List<Taint> sourceTaints, TaintPosition taintPosition) {
        if (obj == null) {
            return false;
        }
        int objHash = HashUtils.calcHashCode(obj);
        if (this.tracingContext.isHitTaintPool(objHash)) {
            Taint taint = new Taint(obj, objHash);
            taint.setTaintPosition(taintPosition); // 记录当前污点到底来自哪个位置
            sourceTaints.add(taint);
            return true;
        }
        // 复合数据类型进行递归拆分, String[]类型在bytebuddy下也会变成Object[]类型
        if (obj instanceof Object[]) {
            Object[] taintArray = (Object[]) obj;
            for (Object taintObj : taintArray) {
                if (isHitTaintPool(taintObj, sourceTaints, taintPosition)) {
                    return true;
                }
            }
        }
        return false;
    }

    private void captureMethodState(TaintPositions sources, TaintPositions targets, Object caller, Object[] args, Object ret, NodeTypeEnum nodeType, OriginCaller originCaller, HookRule hookRule, MethodEvent methodEvent) {
        boolean isHitTaintPool = false;
        ArrayList<Taint> sourceTaints = new ArrayList<>();
        if (sources != null) {
            for (TaintPosition taintPosition : sources.getPositions()) {
                Object taintValue = getTaintByPosition(taintPosition, caller, args, ret);
                int taintHash;
                if (taintPosition.getPositionType().equals(PositionTypeEnum.CALLER) && nodeType.equals(NodeTypeEnum.PROPAGATOR) && originCaller != null) {
                    // 传播节点的caller对象的hash在onmethodenter阶段生成
                    // 这种情况不需要再考虑了，因为java对Object对象的hashcode计算方式是根据地址的
                    taintHash = originCaller.callerHash;
                    if (this.tracingContext.isHitTaintPool(taintHash)) {
                        Taint taint = new Taint(taintValue, taintHash);
                        taint.setTaintPosition(taintPosition);
                        sourceTaints.add(taint);
                    }
                } else {
                    isHitTaintPool(taintValue, sourceTaints, taintPosition);
                }
            }
            if (sources.getRelation().equals("AND")) {
                isHitTaintPool = sources.getPositions().size() <= sourceTaints.size();
            } else {
                isHitTaintPool = !sourceTaints.isEmpty();
            }
        }

        ArrayList<Taint> targetTaints = new ArrayList<>();
        switch (nodeType) {
            case SOURCE:
                Logger.debug("命中规则：" + hookRule);
                for (TaintPosition taintPosition : targets.getPositions()) {
                    Object taintValue = getTaintByPosition(taintPosition, caller, args, ret);
                    Logger.debug("当前污点值：" + taintValue);
                    Taint taint = new Taint(taintValue);
                    taint.setTaintPosition(taintPosition);
                    targetTaints.add(taint);
                    this.tracingContext.addTaint(taint); // 放入污点池
                }
                methodEvent.setSpanID(this.tracingContext.getCurrentSpanID());
                methodEvent.setHookRule(hookRule).setSourceTaints(sourceTaints).setTargetTaints(targetTaints);
                this.tracingContext.addMethodToSegment(methodEvent);
                break;
            case PROPAGATOR:
            case SANITIZER:
                if (isHitTaintPool) {
                    Logger.debug("命中规则：" + hookRule);
                    // todo: 类似于集合这种复合数据类型需要拆分后再加入污点池中吗 ，答：不需要
                    for (TaintPosition taintPosition : targets.getPositions()) {
                        Object taintValue = getTaintByPosition(taintPosition, caller, args, ret);
                        Logger.debug("当前污点值：" + taintValue);

                        Taint taint = new Taint(taintValue);
                        taint.setTaintPosition(taintPosition);
//                        Logger.debug("当前污点hash:" + taint.getHash());
                        this.tracingContext.addTaint(taint); // 放入污点池
                        targetTaints.add(taint);
                        Logger.debug("当前污点数组：" + targetTaints);
                    }
                    methodEvent.setSpanID(this.tracingContext.getCurrentSpanID());
                    methodEvent.setHookRule(hookRule).setSourceTaints(sourceTaints).setTargetTaints(targetTaints);
                    this.tracingContext.addMethodToSegment(methodEvent);
                }
                break;
            case SINK:
                if (isHitTaintPool) {
                    Logger.debug("命中规则：" + hookRule);
                    Logger.info("发现漏洞！");
                    methodEvent.setSpanID(this.tracingContext.getCurrentSpanID());
                    methodEvent.setHookRule(hookRule).setSourceTaints(sourceTaints).setTargetTaints(targetTaints);
                    this.tracingContext.addMethodToSegment(methodEvent);
                }
                break;
        }
    }

    /**
     * 根据类信息和方法信息得到方法全限定名
     * @param cls 类
     * @param exe 方法
     * @return 方法全限定名称
     */
    public String calcMethodFullName(Class<?> cls, Executable exe) {
        String clsName = cls.getName();
        String methodName = exe.getName();
        // todo: 此处逗号后面有空格，以后在编写规则的时候需要格外小心，后续优化此处
        String paramTypes = Arrays.stream(exe.getParameterTypes()).map(Class::getCanonicalName).collect(Collectors.joining(", "));
        if (clsName.equals(methodName)) {
            methodName = "<init>";
        }
        return String.format("%s.%s(%s)", clsName, methodName, paramTypes);
    }
    public void trackMethodCall(NodeTypeEnum nodeType, Class<?> cls, Object caller, Executable exe, Object[] args,
                                Object ret, OriginCaller originCaller) {
        if (!nodeType.equals(NodeTypeEnum.SOURCE) && this.tracingContext.isTaintPoolEmpty()) {
            return;
        }
        String methodFullName = calcMethodFullName(cls, exe);
        HookRule currentHookRule = HookRuleUtils.getHookRule(methodFullName);
        MethodEvent methodEvent = new MethodEvent();
        methodEvent.setMethodFullName(methodFullName);
        List<String> stack = Stream.of(Thread.currentThread().getStackTrace()).map(StackTraceElement::toString).collect(Collectors.toList());
        methodEvent.setStack(stack);
        if (currentHookRule == null) {
            return;
        }
        TaintPositions sources = currentHookRule.getTaintSources();
        TaintPositions targets = currentHookRule.getTaintTargets();
        captureMethodState(sources, targets, caller, args, ret, nodeType, originCaller, currentHookRule, methodEvent);
    }

    public HttpRequest parseRequest(Object request) {
        HttpRequest httpRequest = new HttpRequest();
        try {
            httpRequest.setMethod((String) ReflectionUtils.invoke(request, "getMethod", null));
            httpRequest.setServerName((String) ReflectionUtils.invoke(request, "getServerName", null));
            httpRequest.setServerPort((int) ReflectionUtils.invoke(request, "getServerPort", null));
            httpRequest.setUri((String) ReflectionUtils.invoke(request, "getRequestURI", null));
            httpRequest.setQuery((String) ReflectionUtils.invoke(request, "getQueryString", null));
            httpRequest.setProtocol((String) ReflectionUtils.invoke(request, "getProtocol", null));
            httpRequest.setScheme((String) ReflectionUtils.invoke(request, "getScheme", null));
            Enumeration<?> headerNames = (Enumeration<?>) ReflectionUtils.invoke(request, "getHeaderNames", null);
            Map<String, String> headers = new LinkedHashMap<>();
            while (headerNames.hasMoreElements()) {
                String headerName = (String) headerNames.nextElement();
                String headerValue = (String) ReflectionUtils.invoke(request, "getHeader", new Class[]{String.class},headerName);
                headers.put(headerName, headerValue);
//                System.out.println(headerName + ": " + headerValue);
            }
            httpRequest.setHeaders(headers);
            BufferedReader bufferedReader = (BufferedReader) ReflectionUtils.invoke(request, "getReader", null);
            String line;
            StringBuilder body = new StringBuilder();
            while ((line = bufferedReader.readLine()) != null) {
                body.append(line);
            }
            httpRequest.setBody(body.toString());
            System.out.println(httpRequest);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return httpRequest;
    }

    public HttpResponse parseResponse(HttpResponse httpResponse, Object response) {
        int status = (int) ReflectionUtils.invoke(response, "getStatus", null);
        ArrayList<String> headerNames = (ArrayList<String>) ReflectionUtils.invoke(response, "getHeaderNames", null);
        Map<String, String> headers = new LinkedHashMap<>();
        for(String headerName : headerNames) {
            String headerValue = (String) ReflectionUtils.invoke(response, "getHeader", new Class[]{String.class},headerName);
            headers.put(headerName, headerValue);
        }
        httpResponse.setStatus(status);
        httpResponse.setHeaders(headers);
        return httpResponse;
    }

    @Override
    public void enterEntry(Class<?> cls, Object caller, Executable exe, Object[] args) {
        Logger.info("进入entry");
        HttpRequest httpRequest = parseRequest(args[0]);
        this.tracingContext = this.vulCheckContext.getTracingContextManager().getContext();
        this.tracingContext.setHttpRequet(httpRequest);
        this.tracingContext.enterEntry();
    }
    // todo: 通过hook拿到HttpResponse的原始报文
//    private String parseHttpResponse(Object response) {
//        ByteArrayOutputStream baos = new ByteArrayOutputStream();
//
//        BufferedWriter bufferedWriter = (BufferedWriter) ReflectionUtils.invoke(response, "getWriter", null);
//        bufferedWriter.write();
//    }
    @Override
    public void exitEntry(Class<?> cls, Object caller, Executable exe, Object[] args) {
//         todo: 发送segment到VulScanner进行分析
        this.tracingContext.exitEntry();
        // todo: 这里可能会留坑，对于那些不是springboot框架的javaweb应用，这里的getHttpResponse将返回空，报空指针异常
        parseResponse(this.tracingContext.getHttpResponse(), args[1]);
//        String segmentJson = this.tracingContext.getSegment().get().toJson();
        String segmentJson = this.tracingContext.toJson();
        this.vulCheckContext.report(segmentJson);
        if (this.tracingContext.isValidEntry()) {
            this.tracingContext.reset(); // 重置tracingContext状态
        }
        Logger.info("离开entry");

    }

    @Override
    public void enterSource() {
//        this.tracingContext.enterAgent();
//        Logger.debug("进入source节点");
//        this.tracingContext.exitAgent();
        this.tracingContext.enterSource();
    }

    @Override
    public void exitSource(Class<?> cls, Object caller, Executable exe, Object[] args, Object ret) {
        if (this.tracingContext.isValidSource()) {
            this.tracingContext.enterAgent();
            trackMethodCall(NodeTypeEnum.SOURCE, cls, caller, exe, args, ret, null);
            this.tracingContext.exitAgent();
        }
        // 下面两行代码不能调换位置，因为Logger.debug里有很多字符串拼接操作，如果调换了位置，如果在trackmethodcall打印命中的hookrule,
        // 会发现source节点内还出现了很多传播节点调用，这在我的设计里是不允许的
//        this.tracingContext.enterAgent();
//        Logger.debug("退出source节点");
//        this.tracingContext.exitAgent();
        this.tracingContext.exitSource();
    }
    @Override
    public OriginCaller enterPropagator(Class<?> cls, Object caller, Executable executable, Object[] args) {
        this.tracingContext.enterPropagator();
        OriginCaller originalCaller = new OriginCaller();
        try {
            int callerHash = 0;
            HookRule currentHookRule = null;
            if (this.tracingContext.isValidPropagator() && !this.tracingContext.isTaintPoolEmpty()) {
                this.tracingContext.enterAgent(); // 进入agent代码执行范围
                currentHookRule = HookRuleUtils.getHookRule(calcMethodFullName(cls, executable));
                if (currentHookRule.getIn().contains("O")) {
                    callerHash = HashUtils.calcHashCode(caller);
                }
                this.tracingContext.exitAgent(); // 退出agent代码执行范围
            }
            originalCaller.callerHash = callerHash;
            originalCaller.hookRule = currentHookRule;
            return originalCaller;
        } catch (Exception e) {
            return originalCaller;
        }
    }

    @Override
    public void exitPropagator(Class<?> cls, Object caller, Executable exe, Object[] args, Object ret, OriginCaller originalCaller) {
        try {
            // fix: 在退出的时候捕获caller会有问题，因为此时的caller已经是被当前方法修改过后的caller了，例如对于StringBuilder.append(java.lang.String)方法，
            if (this.tracingContext.isValidPropagator()) {
                this.tracingContext.enterAgent();
                trackMethodCall(NodeTypeEnum.PROPAGATOR, cls, caller, exe, args, ret, originalCaller);
                this.tracingContext.exitAgent();
            }
            this.tracingContext.exitPropagator();
        } catch (Exception e) {
            Logger.error("退出propagator报错：" + e.getMessage());
            this.tracingContext.exitAgent();
            this.tracingContext.exitPropagator();
            System.out.println(e.getMessage());
        }

    }

    @Override
    public void exitPropagatorWithoutThis(Class<?> cls, Executable executable, Object[] args, Object ret) {
        try {
            if (this.tracingContext.isValidPropagator()) {
                this.tracingContext.enterAgent(); // 进入Agent代码执行范围
                trackMethodCall(NodeTypeEnum.PROPAGATOR, cls, null, executable, args, ret, null);
                this.tracingContext.exitAgent(); // 推出Agent代码执行范围
            }
            this.tracingContext.exitPropagator();
        } catch (Exception e) {
            this.tracingContext.exitAgent();
            this.tracingContext.exitPropagator();
        }

    }


//    @Override
//    public void enterPropagatorWithNoRet(Class<?> cls, Object caller, Executable executable, Object[] args) {
//        vulCheckContext.propagatorDepth.incrementAndGet();
//    }

    @Override
    public void enterPropagatorWithoutThis() {
        this.tracingContext.enterPropagator();
    }

    @Override
    public void enterConstructorPropagator() {
        this.tracingContext.enterPropagator();
    }

    @Override
    public void exitConstructorPropagator(Class<?> cls, Object caller, Executable executable, Object[] args) {
        try {
            if (this.tracingContext.isValidPropagator()) {
                this.tracingContext.enterAgent();
                trackMethodCall(NodeTypeEnum.PROPAGATOR, cls, caller, executable, args, null, null);
                this.tracingContext.exitAgent();
            }
            this.tracingContext.exitPropagator();
        } catch (Exception e) {
            this.tracingContext.exitAgent();
            this.tracingContext.exitPropagator();
        }

    }


//    @Override
//    public void exitPropagatorWithNoRet(Class<?> cls, Object caller, Executable exe, Object[] args) {
//        if (!vulCheckContext.isValidPropagator()) {
//            vulCheckContext.propagatorDepth.decrementAndGet();
//            return;
//        }
//        trackMethodCall(NodeTypeEnum.PROPAGATOR, cls, caller, exe, args, null, null);
//        vulCheckContext.propagatorDepth.decrementAndGet();
//    }

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
        this.tracingContext.enterAgent();
    }

    @Override
    public void exitAgent() {
        this.tracingContext.exitAgent();
    }

    @Override
    public boolean isEnterAgent() {
        return this.tracingContext.isEnterAgent();
    }

    @Override
    public void enterOther(Class<?> cls, Object caller, Executable exe, Object[] args) {
        if (this.tracingContext.isEnterEntry()) {
            this.tracingContext.enterAgent();
            String fullMethodName = calcMethodFullName(cls, exe);
            if (fullMethodName.equals("org.springframework.http.converter.AbstractHttpMessageConverter.write(java.lang.Object, org.springframework.http.MediaType, org.springframework.http.HttpOutputMessage)")) {
                HttpResponse httpResponse = new HttpResponse();

                try {
                    httpResponse.setBody(Base64.getEncoder().encodeToString(URLEncoder.encode(args[0].toString(), "UTF-8").getBytes(StandardCharsets.UTF_8)));
                } catch (UnsupportedEncodingException e) {
                    throw new RuntimeException(e);
                }
                this.tracingContext.setHttpResponse(httpResponse);
            }
            this.tracingContext.exitAgent();
        }
    }
}
