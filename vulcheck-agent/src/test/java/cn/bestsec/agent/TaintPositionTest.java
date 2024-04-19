package cn.bestsec.agent;

import cn.bestsec.vulcheck.agent.rule.HookRule;
import cn.bestsec.vulcheck.agent.rule.TaintPosition;
import cn.bestsec.vulcheck.agent.rule.TaintPositions;
import cn.bestsec.vulcheck.agent.rule.deserializer.TaintPositionsDeserializer;
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
        taintPosition.setPositionStr("P1");
        assertEquals(taintPosition, HookRule.parseSinglePosition("P1"));
        taintPosition.setPositionType(PositionTypeEnum.CALLER);
        taintPosition.setIndex(0);
        taintPosition.setPositionStr("O");
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
        taintPosition.setPositionStr("P1");
        TaintPosition taintPosition2 = new TaintPosition();
        taintPosition2.setPositionType(PositionTypeEnum.PARAM);
        taintPosition2.setIndex(2);
        taintPosition2.setTracked(true);
        taintPosition2.setPositionStr("P2");
        taintPositions.addPosition(taintPosition);
        taintPositions.addPosition(taintPosition2);
        GsonBuilder gsonBuilder = new GsonBuilder();
        JsonDeserializer<TaintPositions> jsonDeserializer = new TaintPositionsDeserializer();
        gsonBuilder.registerTypeAdapter(TaintPositions.class, jsonDeserializer);
        Gson gson = gsonBuilder.create();
        System.out.println(gson.fromJson(json, TaintPositions.class));
        assertEquals(taintPositions, gson.fromJson(json, TaintPositions.class));
    }

    public void testParseSimplePositions1() {
        TaintPositions taintPositions = new TaintPositions();
        taintPositions.setRelation("AND");
        TaintPosition taintPosition1 = new TaintPosition();
        taintPosition1.setPositionType(PositionTypeEnum.PARAM);
        taintPosition1.setIndex(1);
        taintPosition1.setPositionStr("P1");
        TaintPosition taintPosition2 = new TaintPosition();
        taintPosition2.setPositionType(PositionTypeEnum.PARAM);
        taintPosition2.setIndex(2);
        taintPosition2.setPositionStr("P2");
        taintPositions.addPosition(taintPosition1);
        taintPositions.addPosition(taintPosition2);

        assertEquals(taintPositions, HookRule.parseSimplePositions("P1&P2"));

        TaintPositions taintPositions1 = new TaintPositions();
        TaintPosition taintPosition = new TaintPosition();
        taintPosition.setPositionStr("O");
        taintPosition.setPositionType(PositionTypeEnum.CALLER);
        taintPositions1.addPosition(taintPosition);

        assertEquals(taintPositions1, HookRule.parseSimplePositions("O"));

        TaintPositions taintPositions2 = new TaintPositions();
        taintPositions2.setRelation("OR");
        TaintPosition taintPosition3 = new TaintPosition();
        taintPosition3.setPositionType(PositionTypeEnum.PARAM);
        taintPosition3.setIndex(1);
        taintPosition3.setPositionStr("P1");
        TaintPosition taintPosition4 = new TaintPosition();
        taintPosition4.setPositionType(PositionTypeEnum.PARAM);
        taintPosition4.setIndex(2);
        taintPosition4.setPositionStr("P2");
        taintPositions2.addPosition(taintPosition3);
        taintPositions2.addPosition(taintPosition4);

        assertEquals(taintPositions2, HookRule.parseSimplePositions("P1|P2"));
    }

    public void testParseSimplePosition2() {
        TaintPositions taintPositions = new TaintPositions();
        taintPositions.setRelation("AND");
        TaintPosition taintPosition1 = new TaintPosition();
        taintPosition1.setPositionType(PositionTypeEnum.PARAM);
        taintPosition1.setIndex(1);
        taintPosition1.setPositionStr("P1");
        TaintPosition taintPosition2 = new TaintPosition();
        taintPosition2.setPositionType(PositionTypeEnum.CALLER);
        taintPosition2.setIndex(0);
        taintPosition2.setPositionStr("O");
        taintPositions.addPosition(taintPosition1);
        taintPositions.addPosition(taintPosition2);

        assertEquals(taintPositions, HookRule.parseSimplePositions("P1&O"));
    }

    public void testParseSimplePosition3() {
        TaintPositions taintPositions = new TaintPositions();
        taintPositions.setRelation("AND");
        TaintPosition taintPosition1 = new TaintPosition();
        taintPosition1.setPositionType(PositionTypeEnum.PARAM);
        taintPosition1.setIndex(1);
        taintPosition1.setPositionStr("P1");
        taintPositions.addPosition(taintPosition1);

        assertEquals(taintPositions, HookRule.parseSimplePositions("P1"));
    }

    public void testParseSimplePosition4() {
        TaintPositions taintPositions = new TaintPositions();
        taintPositions.setRelation("AND");
        TaintPosition taintPosition1 = new TaintPosition();
        taintPosition1.setPositionType(PositionTypeEnum.RET);
        taintPosition1.setIndex(0);
        taintPosition1.setPositionStr("R");
        taintPositions.addPosition(taintPosition1);

        assertEquals(taintPositions, HookRule.parseSimplePositions("R"));
    }

    public void testParseSimplePosition5() {
        TaintPositions taintPositions = new TaintPositions();
        taintPositions.setRelation("AND");
        TaintPosition taintPosition1 = new TaintPosition();
        taintPosition1.setPositionType(PositionTypeEnum.RET);
        taintPosition1.setIndex(0);
        taintPosition1.setPositionStr("R");
        TaintPosition taintPosition2 = new TaintPosition();
        taintPosition2.setPositionType(PositionTypeEnum.CALLER);
        taintPosition2.setIndex(0);
        taintPosition2.setPositionStr("O");
        taintPositions.addPosition(taintPosition1);
        taintPositions.addPosition(taintPosition2);

        assertEquals(taintPositions, HookRule.parseSimplePositions("R&O"));
    }

    public void testParseSimplePosition6() {
        TaintPositions taintPositions = new TaintPositions();
        taintPositions.setRelation("OR");
        TaintPosition taintPosition1 = new TaintPosition();
        taintPosition1.setPositionType(PositionTypeEnum.CALLER);
        taintPosition1.setIndex(0);
        taintPosition1.setPositionStr("O");
        TaintPosition taintPosition2 = new TaintPosition();
        taintPosition2.setPositionType(PositionTypeEnum.PARAM);
        taintPosition2.setIndex(1);
        taintPosition2.setPositionStr("P1");
        taintPositions.addPosition(taintPosition1);
        taintPositions.addPosition(taintPosition2);

        assertEquals(taintPositions, HookRule.parseSimplePositions("O|P1"));
    }
}
