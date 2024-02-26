package cn.bestsec.agent;

import cn.bestsec.vulcheck.agent.HookRule;
import cn.bestsec.vulcheck.agent.TaintPosition;
import cn.bestsec.vulcheck.agent.TaintPositions;
import cn.bestsec.vulcheck.agent.TaintPositionsDeserializer;
import cn.bestsec.vulcheck.agent.enums.PositionTypeEnum;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializer;
import junit.framework.TestCase;

/**
 * 测试污点位置解析是否工作正常
 * @author hjx
 * @since 2024/2/26
 */
public class TaintPositionTest extends TestCase {
    public TaintPositionTest( String testName )
    {
        super( testName );
    }

    public void testParseSinglePosition() {
        TaintPosition taintPosition = new TaintPosition();
        taintPosition.setPositionType(PositionTypeEnum.PARAM);
        taintPosition.setIndex(1);
        assertEquals(taintPosition, HookRule.parseSinglePosition("P1"));
        taintPosition.setPositionType(PositionTypeEnum.CALLER);
        taintPosition.setIndex(0);
        assertEquals(taintPosition, HookRule.parseSinglePosition("O"));
    }

    public void testTaintPositionsDeserializer() {
        String json = "{\n" +
                "\"relation\": \"and\",\n" +
                "\"positions\": [\n" +
                "    {\"position\": \"P1\", \"track\": false, \"bad-value-regex\": \"location\"},\n" +
                "    {\"position\": \"P2\", \"track\": true}\n" +
                "]}";
        TaintPositions taintPositions = new TaintPositions();
        taintPositions.setRelation("AND");
        TaintPosition taintPosition = new TaintPosition();
        taintPosition.setPositionType(PositionTypeEnum.PARAM);
        taintPosition.setIndex(1);
        taintPosition.setTracked(false);
        taintPosition.setBadValueRegex("location");
        TaintPosition taintPosition2 = new TaintPosition();
        taintPosition2.setPositionType(PositionTypeEnum.PARAM);
        taintPosition2.setIndex(2);
        taintPosition2.setTracked(true);
        taintPositions.addPosition(taintPosition);
        taintPositions.addPosition(taintPosition2);
        GsonBuilder gsonBuilder = new GsonBuilder();
        JsonDeserializer<TaintPositions> jsonDeserializer = new TaintPositionsDeserializer();
        gsonBuilder.registerTypeAdapter(TaintPositions.class, jsonDeserializer);
        Gson gson = gsonBuilder.create();
        System.out.println(gson.fromJson(json, TaintPositions.class));
        assertEquals(taintPositions, gson.fromJson(json, TaintPositions.class));
    }

    public void testParseSimplePositions() {
        TaintPositions taintPositions = new TaintPositions();
        taintPositions.setRelation("AND");
        TaintPosition taintPosition1 = new TaintPosition();
        taintPosition1.setPositionType(PositionTypeEnum.PARAM);
        taintPosition1.setIndex(1);
        TaintPosition taintPosition2 = new TaintPosition();
        taintPosition2.setPositionType(PositionTypeEnum.PARAM);
        taintPosition2.setIndex(2);
        taintPositions.addPosition(taintPosition1);
        taintPositions.addPosition(taintPosition2);

        assertEquals(taintPositions, HookRule.parseSimplePositions("P1&P2"));

        TaintPositions taintPositions1 = new TaintPositions();
        TaintPosition taintPosition = new TaintPosition();
        taintPosition.setPositionType(PositionTypeEnum.CALLER);
        taintPositions1.addPosition(taintPosition);

        assertEquals(taintPositions1, HookRule.parseSimplePositions("O"));

        TaintPositions taintPositions2 = new TaintPositions();
        taintPositions2.setRelation("OR");
        TaintPosition taintPosition3 = new TaintPosition();
        taintPosition3.setPositionType(PositionTypeEnum.PARAM);
        taintPosition3.setIndex(1);
        TaintPosition taintPosition4 = new TaintPosition();
        taintPosition4.setPositionType(PositionTypeEnum.PARAM);
        taintPosition4.setIndex(2);
        taintPositions2.addPosition(taintPosition3);
        taintPositions2.addPosition(taintPosition4);

        assertEquals(taintPositions2, HookRule.parseSimplePositions("P1|P2"));
    }
}
