package cn.bestsec.vulcheck.agent.trace;

/**
 * 一次方法调用
 * @author hjx
 * @since 2024/2/8
 */
public interface Span {
    /**
     * 获取spanID
     * @return int spanID
     */
    int getSpanID();

    /**
     * 设置spanID
     */
    void setSpanID(int spanID);
}
