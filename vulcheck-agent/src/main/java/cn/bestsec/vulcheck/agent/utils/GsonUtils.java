package cn.bestsec.vulcheck.agent.utils;

import cn.bestsec.vulcheck.agent.HookRule;
import cn.bestsec.vulcheck.agent.HookRuleDeserializer;
import cn.bestsec.vulcheck.agent.TaintPositions;
import cn.bestsec.vulcheck.agent.TaintPositionsDeserializer;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 * @author
 * @description
 * @since
 */
public class GsonUtils {
    public static <T> T fromJson(String json, Class<T> type) {
        GsonBuilder gsonBuilder = new GsonBuilder();
        HookRuleDeserializer hookRuleDeserializer = new HookRuleDeserializer();
        TaintPositionsDeserializer taintPositionsDeserializer = new TaintPositionsDeserializer();
        gsonBuilder.registerTypeAdapter(HookRule.class, hookRuleDeserializer);
        gsonBuilder.registerTypeAdapter(TaintPositions.class, taintPositionsDeserializer);
        Gson gson = gsonBuilder.create();
        return gson.fromJson(json, type);
    }
}
