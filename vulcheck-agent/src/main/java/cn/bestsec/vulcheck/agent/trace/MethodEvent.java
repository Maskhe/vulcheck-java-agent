package cn.bestsec.vulcheck.agent.trace;

import cn.bestsec.vulcheck.agent.rule.HookRule;
import cn.bestsec.vulcheck.agent.enums.NodeTypeEnum;
import cn.bestsec.vulcheck.agent.utils.GsonUtils;
import lombok.Data;

import java.util.ArrayList;

/**
 * 方法调用事件
 */
@Data
public class MethodEvent implements Span  {
    /**
     * 用于标识一次方法调用的唯一ID
     */
    private int spanID;
    /**
     * 方法类型：source、propagator等
     */
    private NodeTypeEnum nodeType;
    /**
     * 事件类型
     */
    private String eventType;
    /**
     * 本次方法调用命中的hook规则
     */
    private HookRule hookRule;

    ArrayList<Taint> sourceTaints;
    ArrayList<Taint> targetTaints;

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

    public MethodEvent() {
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
        return this.nodeType.equals(NodeTypeEnum.SINK);
    }

    public boolean isSource() {
        return this.nodeType.equals(NodeTypeEnum.SOURCE);
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

    public MethodEvent setSourceTaints(ArrayList<Taint> taints) {
        this.sourceTaints = taints;
        return this;
    }

    public MethodEvent setTargetTaints(ArrayList<Taint> taints) {
        this.targetTaints = taints;
        return this;
    }

    public MethodEvent setHookRule(HookRule hookRule) {
        this.hookRule = hookRule;
        this.nodeType = hookRule.getType();
        this.eventType = hookRule.getEventType();
        return this;
    }

    public MethodEvent setNodeType(NodeTypeEnum nodeType) {
        this.nodeType = nodeType;
        return this;
    }

    public NodeTypeEnum getNodeType() {
        return this.nodeType;
    }

    public MethodEvent setEventType(String eventType) {
        this.eventType = eventType;
        return this;
    }

    @Override
    public String toJson() {
        return GsonUtils.toJson(this);
    }
}
