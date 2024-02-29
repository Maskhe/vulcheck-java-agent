package cn.bestsec.vulcheck.agent;
import cn.bestsec.vulcheck.agent.enums.InheritTypeEnum;
import cn.bestsec.vulcheck.agent.enums.NodeTypeEnum;
import cn.bestsec.vulcheck.agent.enums.PositionTypeEnum;
import cn.bestsec.vulcheck.agent.utils.GsonUtils;
import com.google.gson.annotations.SerializedName;
import lombok.Data;


/**
 * hook规则实体类
 * @author hjx
 * @since 2023/12/10
 */
@Data
public class HookRule {
    @SerializedName("id")
    String id;
    // 类全限定名称
    @SerializedName("class_name")
    String className;
    // 方法名
    @SerializedName("method_name")
    String methodName;
    // 方法签名
    String signature;
    // 方法描述符
    String descriptor;
    // 规则类型: source | propagator | sink | filter
    @SerializedName("rule_type")
    NodeTypeEnum type;
    // 危险入参位置：Pn(参数，第几个形参是污点n的值就为数字几，例如，第一个参数是污点危险入参就是P1，第二个参数是污点，危险入参就是P2) | O(调用当前方法的对象) | R(当前方法返回值)；
    // 出参入参的位置都可能是多个，例如入参为O&P1,表示当调用当前方法的对象和第一个参数都可控时，才会污染出参。出参的位置如果是O&P2，表示调用当前方法的对象及第二个参数都被污染了，都需要放入污点池。
    // 入参的位置为O|P1时表示当调用当前方法的对象或者第一个参数是污点时，就会污染出参。
    @SerializedName("in_param")
    String in;
    // 危险出参位置
    @SerializedName("out_param")
    String out;
    // 继承类型:
    InheritTypeEnum inherit;
    // 事件类型：sql注入、ssrf、字符串操作等
    @SerializedName("event_type")
    String eventType;
    // 当type为SANITIZER时生效，指定当前sanitizer可以对哪些漏洞类型进行免疫
    @SerializedName("immune_vul_type")
    String immuneVulTypes;
    // 是否跟踪
    String tracked;
    // 污点来源位置
    TaintPositions taintSources;
    // 污点目标位置
    TaintPositions taintTargets;

    public HookRule(String id, String className, String methodName, String signature, String descriptor, NodeTypeEnum type,
                    String in, String out, InheritTypeEnum inherit, String eventType, String immuneVulTypes, String tracked) {
        this.id = id;
        this.className = className;
        this.methodName = methodName;
        this.signature = signature;
        this.descriptor = descriptor;
        this.type = type;
        this.in = in;
        this.out = out;
        this.inherit = inherit;
        this.eventType = eventType;
        this.immuneVulTypes = immuneVulTypes;
        this.tracked = tracked;
    }

    public static TaintPositions parsePositions(String positions) {
        if (positions.isEmpty()) {
            return null;
        }
        if(positions.contains("{")) {
            return parseComplexPositions(positions);
        } else {
            return parseSimplePositions(positions);
        }
    }

    public static TaintPositions parseComplexPositions(String positions) {
        return GsonUtils.fromJson(positions, TaintPositions.class);
    }
    public static TaintPositions parseSimplePositions(String positions) {
        TaintPositions taintPositions = new TaintPositions();
        String[] positionArray;
        if (positions.contains("&")) {
            taintPositions.setRelation("AND");
            positionArray = positions.split("&");
        } else if (positions.contains("|")) {
            taintPositions.setRelation("OR");
            positionArray = positions.split("\\|");
        } else {
            taintPositions.addPosition(parseSinglePosition(positions));
            return taintPositions;
        }
        for (String position : positionArray) {
            TaintPosition taintPosition = parseSinglePosition(position);
            taintPositions.addPosition(taintPosition);
        }
        return taintPositions;
    }
    public static TaintPosition parseSinglePosition(String position) {
        String positionType = position.substring(0,1).toUpperCase();
        TaintPosition taintPosition = new TaintPosition();
        switch(positionType){
            case "P":
                taintPosition.setPositionType(PositionTypeEnum.PARAM);
                taintPosition.setIndex(Integer.parseInt(position.substring(1,2)));
                break;
            case "R":
                taintPosition.setPositionType(PositionTypeEnum.RET);
                break;
            case "O":
                taintPosition.setPositionType(PositionTypeEnum.CALLER);
                break;
        }
        return taintPosition;
    }
}
