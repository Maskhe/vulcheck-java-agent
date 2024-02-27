package cn.bestsec.vulcheck.agent;

import com.google.gson.*;

import java.lang.reflect.Type;

/**
 * @author
 * @description
 * @since
 */
public class HookRuleDeserializer implements JsonDeserializer<HookRule> {
    @Override
    public HookRule deserialize(JsonElement jsonElement, Type type, JsonDeserializationContext jsonDeserializationContext) throws JsonParseException {
        JsonObject jsonObject = jsonElement.getAsJsonObject();
        String id = jsonObject.get("id").getAsString();
        String className = jsonObject.get("class_name").getAsString();
        String methodName = jsonObject.get("method_name").getAsString();
        String signature = jsonObject.get("signature").getAsString();
        String descriptor = jsonObject.get("descriptor").getAsString();
        String ruleType = jsonObject.get("rule_type").getAsString();
        String in = jsonObject.get("in_param").getAsString();
        String out = jsonObject.get("out_param").getAsString();
        String inherit = jsonObject.get("inherit").getAsString();
        String eventType = jsonObject.get("event_type").getAsString();
        String immuneVulTypes = jsonObject.get("immune_vul_type").getAsString();
        String tracked = jsonObject.get("tracked").getAsString();
        HookRule hookRule = new HookRule(id, className, methodName, signature, descriptor, ruleType, in, out, inherit, eventType, immuneVulTypes, tracked);
        hookRule.setTaintSources(HookRule.parsePositions(in));
        hookRule.setTaintTargets(HookRule.parsePositions(out));
        return hookRule;
    }
}
