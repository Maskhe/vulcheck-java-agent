package cn.bestsec.vulcheck.agent.trace;

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
        int nextSpanID = currentSpanID ++;
        return currentSpanID;
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
     * 判断一个节点是否为有效sink节点，确保嵌套在source节点内的sink点不执行hook逻辑
     * @return boolean
     */
    public boolean isValidSink() {
        return this.sourceDepth == 0 && this.sinkDepth == 1 && this.agentDepth == 0 && this.entryDepth == 1;
    }

    /**
     * 判断一个节点是否为有效传播节点，确保嵌套在source、propagator、sink节点内的传播节点不执行hook逻辑
     * @return boolean
     */
    public boolean isValidPropagator() {
        return this.sourceDepth == 0 && this.propagatorDepth == 1 && this.sinkDepth == 0 && this.agentDepth == 0 && this.entryDepth == 1;
    }

    /**
     * 判断一个节点是否为有效source节点，确保source节点不嵌套
     * @return boolean
     */
    public boolean isValidSource() {
        return this.sourceDepth == 1 && this.entryDepth > 0 && this.agentDepth == 0;
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
        this.sourceDepth = this.decrement(this.sourceDepth);
    }

    public void exitPropagator() {
        this.propagatorDepth  = this.decrement(this.propagatorDepth);
    }

    public void exitSink() {
        this.sinkDepth  = this.decrement(this.sinkDepth);
    }

    public void exitSanitizer() {
        this.sanitizerDepth  = this.decrement(this.sanitizerDepth);
    }

    HashMap<Integer, Taint> getTaintPool() {
        return this.taintPool.get();
    }

    /**
     * 扣减操作，在springboot启动过程中发现propagatorDepth经常被扣减为负数，推测时由于多线程导致的，解决方案参考Dongtai-agent-java
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
}
