package cn.bestsec.vulcheck.agent.trace;

import cn.bestsec.vulcheck.agent.HookRule;
import cn.bestsec.vulcheck.agent.enums.NodeType;

import java.util.ArrayList;

/**
 * 方法调用事件
 */
public class MethodEvent implements Span  {
    /**
     * 用于标识一次方法调用的唯一ID
     */
    private int spanID;
    /**
     * 方法类型：source、propagator等
     */
    private NodeType methodType;
    /**
     * 事件类型
     */
    private String eventType;
    /**
     * 本次方法调用命中的hook规则
     */
    private HookRule hookRule;

    /**
     * 污点入参的值
     */
    ArrayList<Object> sourceValues;
    /**
     * 污点入参的hash
     */
    ArrayList<String> sourceHashes;
    /**
     * 污点出参的值
     */
    ArrayList<Object> targetValues;
    /**
     * 污点出参的hash
     */
    ArrayList<String> targetHashes;
    /**
     * 方法调用时间
     */
    Long invokeTime;
    public MethodEvent(int spanID) {
        this.spanID = spanID;
        this.invokeTime = System.currentTimeMillis();
    }

    @Override
    public int getSpanID() {
        return this.spanID;
    }

    @Override
    public void setSpanID(int spanID) {
        this.spanID = spanID;
    }

    public boolean isSink() {
        return this.methodType.equals(NodeType.SINK);
    }

    public boolean isSource() {
        return this.methodType.equals(NodeType.SOURCE);
    }

    public MethodEvent setSourceValues(ArrayList<Object> sourceValues) {
        this.sourceValues = sourceValues;
        return this;
    }

    public MethodEvent setSourceHashes(ArrayList<String> sourceHashes) {
        this.sourceHashes = sourceHashes;
        return this;
    }

    public MethodEvent setTargetValues(ArrayList<Object> targetValues) {
        this.targetValues = targetValues;
        return this;
    }

    public MethodEvent setTargetHashes(ArrayList<String> targetHashes) {
        this.targetHashes = targetHashes;
        return this;
    }
}
