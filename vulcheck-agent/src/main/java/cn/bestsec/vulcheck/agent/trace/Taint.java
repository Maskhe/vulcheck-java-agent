package cn.bestsec.vulcheck.agent.trace;

import cn.bestsec.vulcheck.agent.rule.TaintPosition;
import cn.bestsec.vulcheck.agent.utils.HashUtils;

/**
 * 污点的封装对象
 * @author hjx
 */
public class Taint {
    public Taint(Object value) {
        this.value = value;
        this.hash = HashUtils.calcHashCode(value);
    }

    public Taint(Object value, int hash) {
        this.value = value;
        this.hash = hash;
    }

    private final Object value;
    private final int hash;
    private TaintPosition taintPosition;
    public String getValueString() {
        return this.value.toString();
    }

    public int getHash() {
        return this.hash;
    }

    public Taint setTaintPosition(TaintPosition taintPosition) {
        this.taintPosition = taintPosition;
        return this;
    }

    public String getPosition() {
        return this.taintPosition.getPositionStr();
    }
    public String toJson() {
        return String.format("{\"value\":\"%s\", \"hash\": %d, \"position\":\"%s\"}", value.toString(), hash, taintPosition.getPositionStr());
    }

    public String toString() {
        return String.format("{\"value\":\"%s\", \"hash\": %d, \"position\":\"%s\"}", value.toString(), hash, taintPosition.getPositionStr());
    }
}
