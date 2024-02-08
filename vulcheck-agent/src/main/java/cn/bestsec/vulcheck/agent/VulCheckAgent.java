package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.agent.advice.*;
import cn.bestsec.vulcheck.agent.enums.InheritTypeEnum;
import cn.bestsec.vulcheck.agent.enums.NodeType;
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
import java.util.jar.JarFile;
import cn.bestsec.vulcheck.agent.utils.FileUtils;
import org.tinylog.Logger;


/**
 * VulCheck入口
 * @author tntaxin
 * @since 2023/11/15
 */
public class VulCheckAgent {
    public static void premain(String args, Instrumentation inst) throws IOException {
        Logger.info("Agent Starting...");
        String spyJarPath = "C:\\Users\\hjx\\tmp\\vulcheck-spy.jar";
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
                transformer = (builder, typeDescription, classLoader, javaModule, protectionDomain) -> {
                    builder = builder.visit(buildMethodMatchers(hookRule, typeDescription));
                    return builder;
                };
                if (hookRule.inherit.equalsIgnoreCase(InheritTypeEnum.ALL.getName()) || hookRule.inherit.equalsIgnoreCase(InheritTypeEnum.SUBCLASSES.getName())) {
                    agentBuilder = agentBuilder.type(ElementMatchers.hasSuperType(ElementMatchers.named(className))).transform(transformer);
                } else {
                    agentBuilder = agentBuilder.type(ElementMatchers.named(className)).transform(transformer);
                }
            }
        }
        agentBuilder.installOn(inst);
    }

    public static AsmVisitorWrapper buildMethodMatchers(HookRule hookRule, TypeDescription typeDescription) {
        String signature = hookRule.getSignature();
        String methodName = hookRule.getMethodName();
        VulCheckContext vulCheckContext = VulCheckContext.newInstance();
        String uniqueMethod = typeDescription.getCanonicalName() + "." + signature;
        vulCheckContext.addMatchedHookPoint(uniqueMethod, hookRule);
        ElementMatcher.Junction<MethodDescription> elementMatcher;
        if (methodName.equals("<init>")){
            elementMatcher = ElementMatchers.isConstructor();
        }else {
            elementMatcher = ElementMatchers.isMethod().and(ElementMatchers.named(methodName));
        }
        if (hookRule.getType().equalsIgnoreCase(NodeType.ENTRY.getName())) {
            return Advice.to(EntryAdvice.class).on(elementMatcher);
        }else if (hookRule.getType().equalsIgnoreCase(NodeType.SOURCE.getName())) {
            return Advice.to(SourceAdvice.class).on(elementMatcher);
        }  else if (hookRule.getType().equalsIgnoreCase(NodeType.PROPAGATOR.getName()) && !hookRule.getIn().contains("O") && !hookRule.getOut().contains("O")) {
            return Advice.to(PropagatorWithOutThisAdvice.class).on(elementMatcher);
            // todo: 有没有返回值都可以通过 @Advice.Return获取？
        } else if (hookRule.getType().equalsIgnoreCase(NodeType.PROPAGATOR.getName())) {
            return Advice.to(PropagatorAdvice.class).on(elementMatcher);
        } else if (hookRule.getType().equalsIgnoreCase(NodeType.SANITIZER.getName())){
            // todo: 补充sanitizer逻辑
            return Advice.to(SanitizerAdvice.class).on(elementMatcher);
        } else {
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
