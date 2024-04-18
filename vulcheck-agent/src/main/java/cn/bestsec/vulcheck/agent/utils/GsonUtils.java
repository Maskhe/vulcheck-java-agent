package cn.bestsec.vulcheck.agent.utils;

import cn.bestsec.vulcheck.agent.rule.HookRule;
import cn.bestsec.vulcheck.agent.rule.deserializer.HookRuleDeserializer;
import cn.bestsec.vulcheck.agent.rule.TaintPositions;
import cn.bestsec.vulcheck.agent.rule.deserializer.TaintPositionsDeserializer;
import cn.bestsec.vulcheck.agent.trace.MethodEvent;
import cn.bestsec.vulcheck.agent.trace.Span;
import cn.bestsec.vulcheck.agent.trace.TracingContext;
import cn.bestsec.vulcheck.agent.trace.serializer.MethodEventSerializer;
import cn.bestsec.vulcheck.agent.trace.serializer.TracingContextSerializer;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.lang.reflect.Type;

/**
 * Gson工具类
 * @author hjx
 * @since 2024/4/1
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

    public static String toJson(Object src) {
        GsonBuilder gsonBuilder = new GsonBuilder();
        MethodEventSerializer methodEventSerializer = new MethodEventSerializer();
        TracingContextSerializer tracingContextSerializer = new TracingContextSerializer();
        gsonBuilder.registerTypeAdapter(Span.class, methodEventSerializer);
        gsonBuilder.registerTypeAdapter(TracingContext.class, tracingContextSerializer);
        Gson gson = gsonBuilder.create();
        return gson.toJson(src);
    }
}
