package cn.bestsec.vulcheck.agent.trace;

import org.omg.PortableInterceptor.INACTIVE;

import java.util.HashMap;
import java.util.HashSet;
import java.util.UUID;

/**
 * 污点追踪上下文对象
 * @author hjx
 * @since 2024/2/7
 */
public class TracingContext {
    /**
     * 标识一次请求的唯一ID
     */
    private String globalID;
    /**
     * 当前调用方法的ID,递增
     */
    private int currentSpanID = 0;

    /**
     * 标记是否进入业务入口方法
     */
    private boolean enterEntry = false;
    /**
     * 标记是否进入Agent执行逻辑
     */
    private boolean enterAgent = false;
    /**
     * source节点的嵌套层级
     */
    private int sourceDepth = 0;
    private int propagatorDepth = 0;
    private int sinkDepth = 0;
    private int sanitizerDepth = 0;
    private final Segment segment;
    private final InheritableThreadLocal<HashMap<Integer, Taint>> taintPool = new InheritableThreadLocal<>();

    public TracingContext(Segment segment) {
        this.segment = segment;
        this.globalID = UUID.randomUUID().toString();
        this.taintPool.set(new HashMap<>());
    }

    public void addMethodToSegment(Span span) {
        this.segment.addSpan(span);
    }

    public boolean isEnterAgent() {
        return this.enterAgent;
    }
    public void enterAgent() {
        this.enterAgent = true;
    }

    public void leaveAgent() {
        this.enterAgent = false;
    }

    /**
     * 判断一个节点是否为有效sink节点，确保嵌套在source节点内的sink点不执行hook逻辑
     * @return boolean
     */
    public boolean isValidSink() {
        return this.sourceDepth == 0 && this.sinkDepth == 1;
    }

    /**
     * 判断一个节点是否为有效传播节点，确保嵌套在source、propagator、sink节点内的传播节点不执行hook逻辑
     * @return boolean
     */
    public boolean isValidPropagator() {
        return this.sourceDepth == 0 && this.propagatorDepth == 1 && this.sinkDepth == 0;
    }

    /**
     * 判断一个节点是否为有效source节点，确保source节点不嵌套
     * @return boolean
     */
    public boolean isValidSource() {
        return this.sourceDepth == 1;
    }

    public boolean isValidSanitizer() {
        return this.sourceDepth == 0 && this.propagatorDepth == 0 && this.sinkDepth == 0 && this.sanitizerDepth == 1;
    }

    /**
     * 是否进入业务节点
     * @return boolean
     */
    public boolean isEnterEntry() {
        return this.enterEntry;
    }

    public void enterSource() {
        this.sourceDepth ++;
    }

    public void enterPropagator() {
        this.propagatorDepth ++;
    }

    public void enterSink() {
        this.sinkDepth ++;
    }

    public void enterSanitizer() {
        this.sanitizerDepth ++;
    }

    public void exitSource() {
        this.sourceDepth --;
    }

    public void exitPropagator() {
        this.propagatorDepth --;
    }

    public void exitSink() {
        this.sinkDepth --;
    }

    public void exitSanitizer() {
        this.sanitizerDepth --;
    }

    HashMap<Integer, Taint> getTaintPool() {
        return this.taintPool.get();
    }
}
