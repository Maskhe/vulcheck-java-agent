package cn.bestsec.vulcheck.agent;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.matcher.ElementMatcher;
import net.bytebuddy.matcher.ElementMatchers;

import java.io.*;
import java.lang.instrument.Instrumentation;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;
import java.util.jar.JarFile;

public class VulCheckAgent {
    public static void premain(String args, Instrumentation inst) throws IOException {

        // vulcheck-spy.jar使用BootStrapClassLoader加载
        JarFile jarFile = new JarFile("C:\\Users\\hjx\\IdeaProjects\\vulcheck-java-agent\\vulcheck-spy\\target\\vulcheck-spy.jar");
        inst.appendToBootstrapClassLoaderSearch(jarFile);

        VulCheckContext vulCheckContext = VulCheckContext.newInstance();
        AgentBuilder agentBuilder = new AgentBuilder.Default().ignore(ElementMatchers.nameContains(".bytebuddy"))
                .with(new VulCheckListener()).with(AgentBuilder.RedefinitionStrategy.RETRANSFORMATION)
                .with(AgentBuilder.RedefinitionStrategy.REDEFINITION)
                .with(AgentBuilder.TypeStrategy.Default.REDEFINE)
                .with(AgentBuilder.TypeStrategy.Default.REBASE)
                .disableClassFormatChanges()
                .with(AgentBuilder.InitializationStrategy.NoOp.INSTANCE)
                .with(AgentBuilder.InjectionStrategy.UsingUnsafe.INSTANCE);

        AgentBuilder.Transformer transformer;
        for(Map.Entry<String, ArrayList<HookRule>> entry: vulCheckContext.getHookRules().entrySet()){
            String className = entry.getKey();
            for(HookRule hookRule : entry.getValue()){
                transformer = (builder, typeDescription, classLoader, javaModule, protectionDomain) -> builder.visit(buildMethodMatchers(hookRule, typeDescription));
                agentBuilder = agentBuilder.type(ElementMatchers.hasSuperType(ElementMatchers.named(className))).transform(transformer);
            }
        }
        agentBuilder.installOn(inst);
    }

    public static AsmVisitorWrapper buildMethodMatchers(HookRule hookRule, TypeDescription typeDescription) {
        String methodName = hookRule.getMethodName();
        String descriptor = hookRule.getDescriptor();
        VulCheckContext vulCheckContext = VulCheckContext.newInstance();
        vulCheckContext.addMatchedHookPoint(typeDescription.getCanonicalName() + "." + methodName, hookRule);
        ElementMatcher.Junction<MethodDescription> elementMatcher;
        if (methodName.equals("<init>")){
            elementMatcher = ElementMatchers.isConstructor().and(ElementMatchers.hasDescriptor(descriptor));
        }else {
            elementMatcher = ElementMatchers.isMethod().and(ElementMatchers.named(methodName)).and(ElementMatchers.hasDescriptor(descriptor));
        }
        if (hookRule.getType().equals("source")) {
            return Advice.to(SourceAdvice.class).on(elementMatcher);
        } else if (hookRule.getType().equals("propagator") && hookRule.getOut().equals("ret")) {
            return Advice.to(PropagatorAdvice.class).on(elementMatcher);
        } else if (hookRule.getType().equals("propagator")) {
            return Advice.to(PropagatorWithNoRetAdvice.class).on(elementMatcher);
        } else {
            return Advice.to(SinkAdvice.class).on(elementMatcher);
        }
    }
}
