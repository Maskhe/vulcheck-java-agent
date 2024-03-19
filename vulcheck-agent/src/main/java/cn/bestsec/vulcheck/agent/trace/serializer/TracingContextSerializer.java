package cn.bestsec.vulcheck.agent.trace.serializer;

import cn.bestsec.vulcheck.agent.trace.TracingContext;
import com.google.gson.*;

import java.lang.reflect.Type;

/**
 * @author
 * @description
 * @since
 */
public class TracingContextSerializer implements JsonSerializer<TracingContext> {
    @Override
    public JsonElement serialize(TracingContext tracingContext, Type type, JsonSerializationContext jsonSerializationContext) {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("globalID", tracingContext.getGlobalID());
        jsonObject.addProperty("currentSpanID", tracingContext.getCurrentSpanID());
        jsonObject.add("segment", jsonSerializationContext.serialize(tracingContext.getSegment().get()));
        return jsonObject;
    }
}
