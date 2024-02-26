package cn.bestsec.vulcheck.agent;

import com.google.gson.*;

import java.lang.reflect.Type;

/**
 * 污点位置反序列化器
 * @author hjx
 * @since 2024/2/26
 */
public class TaintPositionsDeserializer implements JsonDeserializer<TaintPositions> {

    @Override
    public TaintPositions deserialize(JsonElement jsonElement, Type type, JsonDeserializationContext jsonDeserializationContext) throws JsonParseException {
        JsonObject jsonObject = jsonElement.getAsJsonObject();
        TaintPositions taintPositions = new TaintPositions();
        JsonArray positions = jsonObject.getAsJsonArray("positions");
        String relation = jsonObject.get("relation").getAsString();
        taintPositions.setRelation(relation.toUpperCase());
        TaintPosition taintPosition;
        for (JsonElement element: positions) {
            JsonObject positionObj = element.getAsJsonObject();
            taintPosition = HookRule.parseSinglePosition(positionObj.get("position").getAsString());
            if (positionObj.has("track")) {
                taintPosition.setTracked(positionObj.get("track").getAsBoolean());
            }
            if (positionObj.has("bad-value-regex")) {
                taintPosition.setBadValueRegex(positionObj.get("bad-value-regex").getAsString());
            }
            taintPositions.addPosition(taintPosition);
        }
        return taintPositions;
    }
}
