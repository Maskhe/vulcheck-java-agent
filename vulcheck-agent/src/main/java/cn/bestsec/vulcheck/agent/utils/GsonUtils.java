package cn.bestsec.vulcheck.agent.utils;

import cn.bestsec.vulcheck.agent.rule.HookRule;
import cn.bestsec.vulcheck.agent.rule.deserializer.HookRuleDeserializer;
import cn.bestsec.vulcheck.agent.rule.TaintPositions;
import cn.bestsec.vulcheck.agent.rule.deserializer.TaintPositionsDeserializer;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.lang.reflect.Type;

/**
 * @author
 * @description
 * @since
 */
public class GsonUtils {
    public static <T> T fromJson(String json, Type type) {
        GsonBuilder gsonBuilder = new GsonBuilder();
        HookRuleDeserializer hookRuleDeserializer = new HookRuleDeserializer();
        TaintPositionsDeserializer taintPositionsDeserializer = new TaintPositionsDeserializer();
        gsonBuilder.registerTypeAdapter(HookRule.class, hookRuleDeserializer);
        gsonBuilder.registerTypeAdapter(TaintPositions.class, taintPositionsDeserializer);
        Gson gson = gsonBuilder.create();
        return gson.fromJson(json, type);
    }
}
