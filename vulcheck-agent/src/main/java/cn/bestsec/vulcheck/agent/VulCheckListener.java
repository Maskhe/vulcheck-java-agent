package cn.bestsec.vulcheck.agent;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.utility.JavaModule;

/**
 * Bytebuddy AgentBuilder监视器，可监控改写字节码过程中bytebuddy的行为，利用调试
 * @author tntaxin
 * @since 2023/11/16
 */
public class VulCheckListener implements AgentBuilder.Listener {
    @Override
    public void onDiscovery(String s, ClassLoader classLoader, JavaModule javaModule, boolean b) {

    }

    @Override
    public void onTransformation(TypeDescription typeDescription, ClassLoader classLoader, JavaModule javaModule, boolean b, DynamicType dynamicType) {
        System.out.println("改写：" + typeDescription.toString());
    }

    @Override
    public void onIgnored(TypeDescription typeDescription, ClassLoader classLoader, JavaModule javaModule, boolean b) {
//        System.out.println("忽略：" + typeDescription.toString() + "类加载器：" + classLoader);
    }

    @Override
    public void onError(String s, ClassLoader classLoader, JavaModule javaModule, boolean b, Throwable throwable) {
        System.out.println("错误：" + s);
        System.out.println(throwable.getMessage());
    }

    @Override
    public void onComplete(String s, ClassLoader classLoader, JavaModule javaModule, boolean b) {

    }
}
