package cn.bestsec.vulcheck.agent.trace;

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
    public String getValueString() {
        return this.value.toString();
    }

    public int getHash() {
        return this.hash;
    }

    public String toJson() {
        return String.format("{\"value\":\"%s\", \"hash\": %d}", value.toString(), hash);
    }

    public String toString() {
        return String.format("{\"value\":\"%s\", \"hash\": %d}", value.toString(), hash);
    }
}
