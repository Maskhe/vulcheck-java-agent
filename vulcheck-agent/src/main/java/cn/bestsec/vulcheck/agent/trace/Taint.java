package cn.bestsec.vulcheck.agent.trace;

/**
 * 污点的封装对象
 */
public class Taint {
    public Taint(Object value) {
        this.value = value;
        this.hash = value.hashCode();
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
        return String.format("{\"value\":\"%s\", \"hash\":\"%d\"}", value.toString(), hash);
    }
}
