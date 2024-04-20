package cn.bestsec.vulcheck.agent.utils;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class ReflectionUtils {
    public static Object invoke(Object obj, String methodName, Class<?>[] paramTypes, Object... args) {
        Class<?> requestClass = obj.getClass();
        try {
            Method method;
            if (paramTypes != null) {
                method = requestClass.getMethod(methodName, paramTypes);
            } else {
                method = requestClass.getMethod(methodName);
            }

            method.setAccessible(true);
            return method.invoke(obj, args);
        } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }

    }
}
