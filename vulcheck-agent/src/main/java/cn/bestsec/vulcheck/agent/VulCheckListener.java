package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.agent.trace.TracingContext;
import cn.bestsec.vulcheck.agent.trace.TracingContextManager;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.utility.JavaModule;
import org.tinylog.Logger;

/**
 * Bytebuddy AgentBuilder监视器，可监控改写字节码过程中bytebuddy的行为，利于调试
 * @author tntaxin
 * @since 2023/11/16
 */
public class VulCheckListener implements AgentBuilder.Listener {
    @Override
    public void onDiscovery(String s, ClassLoader classLoader, JavaModule javaModule, boolean b) {

    }

    @Override
    public void onTransformation(TypeDescription typeDescription, ClassLoader classLoader, JavaModule javaModule, boolean b, DynamicType dynamicType) {
        TracingContext tracingContext = VulCheckContext.newInstance().getTracingContextManager().getContext();
        tracingContext.enterAgent();
        Logger.info(String.format("Transform %s ...", typeDescription.toString()));
        tracingContext.exitAgent();
    }

    @Override
    public void onIgnored(TypeDescription typeDescription, ClassLoader classLoader, JavaModule javaModule, boolean b) {
//        Logger.info("忽略：" + typeDescription.toString() + ", 类加载器" + classLoader);
    }

    @Override
    public void onError(String s, ClassLoader classLoader, JavaModule javaModule, boolean b, Throwable throwable) {
        Logger.error(throwable.getMessage());
    }

    @Override
    public void onComplete(String s, ClassLoader classLoader, JavaModule javaModule, boolean b) {
//        Logger.info(String.format("Transform %s completed.", s));
    }
}
