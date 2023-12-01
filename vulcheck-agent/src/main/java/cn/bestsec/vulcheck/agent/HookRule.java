package cn.bestsec.vulcheck.agent;
import com.google.gson.annotations.SerializedName;
import lombok.Data;


/**
 * hook规则实体类
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
    // 方法描述符
    String descriptor;
    // 规则类型: source | propagator | sink | filter
    @SerializedName("rule_type")
    String type;
    // 危险入参位置：Pn(参数，第几个形参是污点n的值就为数字几，例如，第一个参数是污点危险入参就是P1，第二个参数是污点，危险入参就是P2) | O(调用当前方法的对象) | R(当前方法返回值)；
    // 出参入参的位置都可能是多个，例如入参为O&P1,表示当调用当前方法的对象和第一个参数都可控时，才会污染出参。出参的位置如果是O&P2，表示调用当前方法的对象及第二个参数都被污染了，都需要放入污点池。
    // 入参的位置为O|P1时表示当调用当前方法的对象或者第一个参数是污点时，就会污染出参。
    @SerializedName("in_param")
    String in;
    // 危险出参位置
    @SerializedName("out_param")
    String out;

    public HookRule(String id, String className, String methodName, String descriptor, String type, String in, String out) {
        this.id = id;
        this.className = className;
        this.methodName = methodName;
        this.descriptor = descriptor;
        this.type = type;
        this.in = in;
        this.out = out;
    }
}
