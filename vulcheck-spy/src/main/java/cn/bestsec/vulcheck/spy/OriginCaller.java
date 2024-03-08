package cn.bestsec.vulcheck.spy;

public class OriginCaller {
    @Override
    public String toString() {
        return "OriginCaller{" +
                "callerHash=" + callerHash +
                ", hookRule=" + hookRule +
                '}';
    }

    public int callerHash;
    public Object hookRule;


}
