package cn.bestsec.vulcheck.agent.utils;

import cn.bestsec.vulcheck.agent.rule.HookRule;
import cn.bestsec.vulcheck.agent.VulCheckContext;

import java.lang.reflect.Executable;
import java.util.Arrays;
import java.util.HashMap;
import java.util.stream.Collectors;

/**
 * 处理HookRule对象的工具类
 * @author hjx
 * @since 2024/3/28
 */
public class HookRuleUtils {
    /**
     * 根据类和方法信息获取对应的HookRule对象
     * @param uniqueMethod 方法全名
     * @return HookRule
     */
    public static HookRule getHookRule(String uniqueMethod) {
        VulCheckContext vulCheckContext = VulCheckContext.newInstance();
        HashMap<String, HookRule> matchedHookNodes = vulCheckContext.getMatchedHookNodes();
        return matchedHookNodes.get(uniqueMethod);
    }
}
