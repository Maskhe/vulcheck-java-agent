package cn.bestsec.vulcheck.agent.utils;

import cn.bestsec.vulcheck.agent.HookRule;
import cn.bestsec.vulcheck.agent.VulCheckContext;
import org.tinylog.Logger;

import java.lang.reflect.Executable;
import java.util.Arrays;
import java.util.HashMap;
import java.util.stream.Collectors;

public class HookRuleUtils {
    public static HookRule getHookRule(Class<?> cls, Executable exe) {
        VulCheckContext vulCheckContext = VulCheckContext.newInstance();
        String clsName = cls.getName();
        String methodName = exe.getName();
        String paramTypes = Arrays.stream(exe.getParameterTypes()).map(Class::getCanonicalName).collect(Collectors.joining(", "));
        String uniqueMethod;
        if (clsName.equals(methodName)) {
            methodName = "<init>";
        }
        uniqueMethod = String.format("%s.%s(%s)", clsName, methodName, paramTypes);
        HashMap<String, HookRule> matchedHookNodes = vulCheckContext.getMatchedHookNodes();
        return matchedHookNodes.get(uniqueMethod);
    }
}
