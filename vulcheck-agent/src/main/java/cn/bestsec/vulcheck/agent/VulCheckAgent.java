package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.agent.advice.*;
import cn.bestsec.vulcheck.agent.enums.InheritTypeEnum;
import cn.bestsec.vulcheck.agent.rule.HookRule;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

import java.io.*;
import java.lang.instrument.Instrumentation;
import java.util.*;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarFile;
import cn.bestsec.vulcheck.agent.utils.FileUtils;
import org.tinylog.Logger;


/**
 * VulCheck入口类
 * @author tntaxin
 * @since 2023/11/15
 */
public class VulCheckAgent {
    private static final String OS_NAME = System.getProperty("os.name").toLowerCase();
    private static final String SPY_FILE = "vulcheck-spy.jar";

    /**
     * 根据不同操作系统获取agent jar包的临时存放路径
     * @return temp path
     */
    public static String getTempPath() {
        if (OS_NAME.contains("windows")) {
            return System.getenv("USERPROFILE") + File.separator + "vulcheck_jars";
        }

        return "/tmp/vulcheck_jars";
    }

    public static void premain(String args, Instrumentation inst) throws IOException {
        Logger.info("Agent Starting...");
        String spyJarPath = getTempPath() + File.separator + SPY_FILE;
        FileUtils.extractJars(spyJarPath);
        // vulcheck-spy.jar使用BootStrapClassLoader加载
        JarFile jarFile = new JarFile(spyJarPath);
        inst.appendToBootstrapClassLoaderSearch(jarFile);

        VulCheckContext vulCheckContext = VulCheckContext.newInstance();
        AgentBuilder agentBuilder = new AgentBuilder.Default().ignore(ElementMatchers.nameContains(".bytebuddy"))
                .with(new VulCheckListener()).with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION) // redefinition和retransformation的区别：https://lsieun.github.io/java-agent/s01ch03/redefine-vs-retransform.html
                .with(AgentBuilder.TypeStrategy.Default.REBASE) // rebase和redefine的区别：rebase会将原方法改名并保存，再重写原方法，redefine会直接重写原有方法
                .disableClassFormatChanges() // 配合RedefinitionStrategy使用，重写已加载的类文件时不能更改原类的结构，所以需要这个函数
                .with(AgentBuilder.InitializationStrategy.NoOp.INSTANCE)
                .with(AgentBuilder.InjectionStrategy.UsingUnsafe.INSTANCE);

        AgentBuilder.Transformer transformer;
        for(Map.Entry<String, ArrayList<HookRule>> entry: vulCheckContext.getHookRules().entrySet()){
            String className = entry.getKey();
            for(HookRule hookRule : entry.getValue()){
                Logger.info(hookRule);
                transformer = (builder, typeDescription, classLoader, javaModule, protectionDomain) -> {
                    builder = builder.visit(buildMethodMatchers(hookRule, typeDescription));
                    return builder;
                };
                if (hookRule.getInherit() == InheritTypeEnum.ALL || hookRule.getInherit() == InheritTypeEnum.SUBCLASSES) {
                    agentBuilder = agentBuilder.type(ElementMatchers.hasSuperType(ElementMatchers.named(className))).transform(transformer);
                } else {
                    agentBuilder = agentBuilder.type(ElementMatchers.named(className)).transform(transformer);
                }
            }
        }
//        ScheduledExecutorService executor = new ScheduledThreadPoolExecutor(1);
//        executor.scheduleAtFixedRate(new Reporter(), 10, 10, TimeUnit.SECONDS);
        agentBuilder.installOn(inst);
    }

    public static AsmVisitorWrapper buildMethodMatchers(HookRule hookRule, TypeDescription typeDescription) {
        String signature = hookRule.getSignature();
        String methodName = hookRule.getMethodName();
        String descriptor = hookRule.getDescriptor();
        VulCheckContext vulCheckContext = VulCheckContext.newInstance();
        String uniqueMethod = typeDescription.getCanonicalName() + "." + signature;
        vulCheckContext.addMatchedHookNode(uniqueMethod, hookRule);
        ElementMatcher.Junction<MethodDescription> elementMatcher;
        if (methodName.equals("<init>")){
            elementMatcher = ElementMatchers.isConstructor().and(ElementMatchers.hasDescriptor(descriptor));
        }else {
            elementMatcher = ElementMatchers.isMethod().and(ElementMatchers.named(methodName)).and(ElementMatchers.hasDescriptor(descriptor));
        }

        switch(hookRule.getType()) {
            case ENTRY:
                return Advice.to(EntryAdvice.class).on(elementMatcher);
            case SOURCE:
                return Advice.to(SourceAdvice.class).on(elementMatcher);
            case PROPAGATOR:
                if(!hookRule.getIn().contains("O") && !hookRule.getOut().contains("O")) {
                    return Advice.to(PropagatorWithoutThisAdvice.class).on(elementMatcher);
                } else if (hookRule.getMethodName().equals("<init>")) {
                    return Advice.to(ConstructorPropagatorAdvice.class).on(elementMatcher);
                } else {
                    return Advice.to(PropagatorAdvice.class).on(elementMatcher);
                }
            case SANITIZER:
                return Advice.to(SanitizerAdvice.class).on(elementMatcher);
            default:
                return Advice.to(SinkAdvice.class).on(elementMatcher);
        }
    }

    private static void outputClazz(byte[] bytes, String className) {
        FileOutputStream out = null;
        try {
//            String pathName = VulCheckAgent.class.getResource("/").getPath() + className + ".class";
            String pathName = "C:\\Users\\hjx\\tmp\\classes\\" + className + ".class";
            out = new FileOutputStream(pathName);
            System.out.println("类输出路径：" + pathName);
            out.write(bytes);
            out.flush();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (null != out) {
                try {
                    out.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
