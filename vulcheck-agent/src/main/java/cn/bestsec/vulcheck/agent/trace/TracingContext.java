package cn.bestsec.vulcheck.agent.trace;

import cn.bestsec.vulcheck.agent.trace.http.HttpRequest;
import cn.bestsec.vulcheck.agent.trace.http.HttpResponse;
import cn.bestsec.vulcheck.agent.utils.GsonUtils;
import cn.bestsec.vulcheck.agent.utils.HashUtils;
import cn.bestsec.vulcheck.agent.utils.PropertyUtils;
import com.google.gson.Gson;
import lombok.Data;
import org.omg.PortableInterceptor.INACTIVE;

import java.util.HashMap;
import java.util.HashSet;
import java.util.UUID;

/**
 * 污点追踪上下文对象
 * @author hjx
 * @since 2024/2/7
 */
@Data
public class TracingContext {
    /**
     * 标识一次请求的唯一ID
     */
    private String globalID;
    /**
     * 当前调用方法的ID,递增
     */
    private int currentSpanID = 0;

    public int getCurrentSpanID() {
        int spanID = this.currentSpanID;
        this.currentSpanID ++;
        return spanID;
    }

    /**
     * 标记是否进入业务入口方法
     */
    private int entryDepth = 0;
    /**
     * 标记是否进入Agent执行逻辑
     */
    private int agentDepth = 0;
    /**
     * source节点的嵌套层级
     */
    private int sourceDepth = 0;
    private int propagatorDepth = 0;
    private int sinkDepth = 0;
    private int sanitizerDepth = 0;
    private final InheritableThreadLocal<Segment> segment = new InheritableThreadLocal<>();
    private final InheritableThreadLocal<HashMap<Integer, Taint>> taintPool = new InheritableThreadLocal<>();
    private String projectName;

    public TracingContext(Segment segment) {
        this.segment.set(segment);
        this.globalID = UUID.randomUUID().toString();
        this.taintPool.set(new HashMap<>());
        this.setProjectName(PropertyUtils.getProjectName());
    }

    public void init() {
        this.globalID = UUID.randomUUID().toString();
        this.initTaintPool();
        this.initSegment();
        this.sourceDepth = 0;
        this.propagatorDepth = 0;
        this.agentDepth = 0;
        this.sinkDepth = 0;
        this.sanitizerDepth = 0;
        this.entryDepth = 0;
    }

    public void addMethodToSegment(Span span) {
        this.segment.get().addSpan(span);
    }

    public boolean isValidEntry() {
        return this.entryDepth == 1;
    }
    public void enterEntry() {
        this.entryDepth ++;
    }

    public void exitEntry() {
        this.entryDepth --;
    }

    public boolean isEnterAgent() {
        return this.agentDepth > 0;
    }
    public void enterAgent() {
        this.agentDepth ++;
    }

    public void exitAgent() {
        this.agentDepth --;
    }

    /**
     * 判断一个节点是否为有效传播节点，确保嵌套在source、propagator、sink节点内的传播节点不执行hook逻辑
     * @return boolean
     */
    public boolean isValidPropagator() {
        return this.agentDepth == 0 && this.entryDepth == 1 && this.sourceDepth == 0 && this.propagatorDepth == 1 && this.sinkDepth == 0;
    }

    /**
     * 判断一个节点是否为有效sink节点，确保嵌套在source节点内的sink点不执行hook逻辑
     * @return boolean
     */
    public boolean isValidSink() {
        return this.agentDepth == 0 && this.entryDepth == 1 && this.sourceDepth == 0 && this.sinkDepth == 1;
    }

    /**
     * 判断一个节点是否为有效source节点，确保source节点不嵌套
     * @return boolean
     */
    public boolean isValidSource() {
        return this.agentDepth == 0 &&this.entryDepth == 1 && this.sourceDepth == 1;
    }

//    public boolean isValidSanitizer() {
//        return this.sourceDepth == 0 && this.propagatorDepth == 0 && this.sinkDepth == 0 && this.sanitizerDepth == 1;
//    }

    /**
     * 是否进入业务节点
     * @return boolean
     */
    public boolean isEnterEntry() {
        return this.entryDepth > 0;
    }

    public void enterSource() {
        if (!this.isEnterEntry() || this.isEnterAgent()) {
            return;
        }
        this.sourceDepth ++;
    }

    public void enterPropagator() {
        if (!this.isEnterEntry() || this.isEnterAgent()) {
            return;
        }
        this.propagatorDepth ++;
    }

    public void enterSink() {
        if (!this.isEnterEntry() || this.isEnterAgent()) {
            return;
        }
        this.sinkDepth ++;
    }

    public void enterSanitizer() {
        this.sanitizerDepth ++;
    }

    public void exitSource() {
        if (!this.isEnterEntry() || this.isEnterAgent()) {
            return;
        }
        this.sourceDepth = this.decrement(this.sourceDepth);
    }

    public void exitPropagator() {
        if (!this.isEnterEntry() || this.isEnterAgent()) {
            return;
        }
        this.propagatorDepth  = this.decrement(this.propagatorDepth);
    }

    public void exitSink() {
        if (!this.isEnterEntry() || this.isEnterAgent()) {
            return;
        }
        this.sinkDepth  = this.decrement(this.sinkDepth);
    }

    public void exitSanitizer() {
        this.sanitizerDepth  = this.decrement(this.sanitizerDepth);
    }

    HashMap<Integer, Taint> getTaintPool() {
        return this.taintPool.get();
    }

    public boolean isTaintPoolEmpty() {
        return this.taintPool.get() == null || this.taintPool.get().isEmpty();
    }

    public boolean isHitTaintPool(int taintHash) {
        return this.taintPool.get().containsKey(taintHash);
    }

    public boolean isHitTaintPool(Object obj) {
        return this.taintPool.get().containsKey(HashUtils.calcHashCode(obj));
    }

    public void addTaint(Taint taint) {
        if (isHitTaintPool(taint.getHash())) {
            return;
        }
        this.taintPool.get().put(taint.getHash(), taint);
    }


    public void initTaintPool() {
        this.taintPool.set(new HashMap<>());
    }
    public void clearTaintPool() {
        this.taintPool.remove();
    }

    public void initSegment() {
        this.segment.set(new Segment(""));
    }
    public void clearSegment() {
        this.segment.remove();
    }

    public void setHttpRequet(HttpRequest httpRequest) {
        this.segment.get().setHttpRequest(httpRequest);
    }

    public void setHttpResponse(HttpResponse httpResponse) {
        this.segment.get().setHttpResponse(httpResponse);
    }

    public HttpResponse getHttpResponse() {
        return this.segment.get().getHttpResponse();
    }

    public void reset() {
        this.clearTaintPool();
        this.clearSegment();
        this.currentSpanID = 0;
//        this.propagatorDepth = 0;
//        this.agentDepth = 0;
    }

    /**
     * 扣减操作，在springboot启动过程中发现propagatorDepth经常被扣减为负数，推测时由于多线程导致的，解决方案参考Dongtai-agent-java
     * https://github.com/HXSecurity/DongTai-agent-java
     * 但是不清楚多线程操作时会不会导致propagatorDepth少扣减
     * @param depth 深度
     * @return 新深度
     */
    private int decrement(int depth) {
        if (depth > 0) {
            return depth - 1;
        }
        return 0;
    }

    public String toJson() {
        return GsonUtils.toJson(this);
    }

    public String toString() {
        return String.format("{\"globalID\": \"%s\",\"projectName\":\"%s\", \"currentSpanID\", \"%s\", \"segment\": \"%s\"}", this.globalID, this.projectName,
                this.currentSpanID, this.segment.get().toJson());
    }
}
