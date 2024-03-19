package cn.bestsec.vulcheck.agent.trace.serializer;

import cn.bestsec.vulcheck.agent.enums.NodeTypeEnum;
import cn.bestsec.vulcheck.agent.trace.MethodEvent;
import cn.bestsec.vulcheck.agent.trace.Taint;
import com.google.gson.*;

import java.lang.reflect.Type;
import java.util.ArrayList;

/**
 * @author
 * @description
 * @since
 */
public class MethodEventSerializer implements JsonSerializer<MethodEvent> {

    @Override
    public JsonElement serialize(MethodEvent methodEvent, Type type, JsonSerializationContext jsonSerializationContext) {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("spanID", methodEvent.getSpanID());
        jsonObject.addProperty("nodeType", methodEvent.getNodeType().getName());
        jsonObject.addProperty("eventType", methodEvent.getEventType());
        jsonObject.addProperty("invokeTime", methodEvent.getInvokeTime());
        JsonArray jsonArray = new JsonArray();
        ArrayList<Taint> taints = methodEvent.getSourceTaints();
        for (Taint taint : taints) {
//            jsonArray.add(taint.toJson());
            jsonArray.add(jsonSerializationContext.serialize(taint));
        }
        jsonObject.add("sourceTaints", jsonArray);
        taints = methodEvent.getTargetTaints();
        jsonArray = new JsonArray();
        for (Taint taint : taints) {
            jsonArray.add(jsonSerializationContext.serialize(taint));
        }
        jsonObject.add("targetTaints", jsonArray);
//        jsonObject.addProperty("sourceTaints", methodEvent.getSourceTaints().to);
        return jsonObject;
    }
}
