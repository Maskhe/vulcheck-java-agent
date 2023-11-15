package cn.bestsec.vulcheck.spy;
import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class HookRule {
    @SerializedName("id")
    String id;
    @SerializedName("class_name")
    String className;
    @SerializedName("method_name")
    String methodName;
    String descriptor;
    @SerializedName("rule_type")
    String type;
    @SerializedName("in_param")
    String in;
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
