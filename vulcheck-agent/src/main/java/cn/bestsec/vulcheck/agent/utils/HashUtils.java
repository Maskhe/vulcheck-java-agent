package cn.bestsec.vulcheck.agent.utils;

/**
 * 计算hashcode的工具类
 * @since 2024/4/2
 * @author hjx
 */
public class HashUtils {
    public static int calcHashCode(Object obj) {
        if (obj instanceof String) {
            return obj.hashCode();
        } else {
            return System.identityHashCode(obj);
        }
    }
}
