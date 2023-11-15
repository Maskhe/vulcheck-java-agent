package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.spy.HookRule;
import cn.bestsec.vulcheck.spy.VulCheckContext;
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

public class VulCheckAgent {
    public static void premain(String args, Instrumentation inst) throws IOException {
        ClassLoader classLoader1 = VulCheckAgent.class.getClassLoader();
        URL url = classLoader1.getResource("vulcheck-spy-1.0-SNAPSHOT.jar");
        System.out.println(url);
        Gson gson = new Gson();
        // 读取服务端hook规则
        String json = "";
        URL uri = new URL("http://localhost:8000/hookrulesmanage/?inUse=1");
        HttpURLConnection connection = (HttpURLConnection) uri.openConnection();
        connection.setRequestMethod("GET");
        connection.connect();
        int responseCode = connection.getResponseCode();
        if(responseCode == HttpURLConnection.HTTP_OK){
            InputStream inputStream = connection.getInputStream();
            InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
            BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
            String line = "";
            StringBuilder response = new StringBuilder();
            while((line = bufferedReader.readLine()) != null){
                response.append(line).append("\n");
            }
            json = response.toString();
        }
        HashMap<String, ArrayList<HookRule>> hookRules = gson.fromJson(json, new TypeToken<HashMap<String, List<HookRule>>>(){}.getType());
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
        for(Map.Entry<String, ArrayList<HookRule>> entry: hookRules.entrySet()){
            String className = entry.getKey();
            for(HookRule hookRule : entry.getValue()){
                transformer = (builder, typeDescription, classLoader, javaModule, protectionDomain) -> builder.visit(buildMethodMatchers(hookRule, typeDescription));
                agentBuilder = agentBuilder.type(ElementMatchers.hasSuperType(ElementMatchers.named(className))).transform(transformer);
            }
        }
        agentBuilder.installOn(inst);
    }

    public static String readFile(String path){
        StringBuilder result = new StringBuilder();
        try(Scanner scanner = new Scanner(new FileReader(path))){
            while(scanner.hasNextLine()){
                result.append(scanner.nextLine());
            }
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        return result.toString();
    }

    public static AsmVisitorWrapper buildMethodMatchers(HookRule hookRule, TypeDescription typeDescription) {
        String methodName = hookRule.getMethodName();
        String descriptor = hookRule.getDescriptor();
        VulCheckContext vulCheckContext = VulCheckContext.newInstance();
        vulCheckContext.addHookRule(typeDescription.getCanonicalName() + "." + methodName, hookRule);
        ElementMatcher.Junction<MethodDescription> elementMatcher;
        if (methodName.equals("<init>")){
            elementMatcher = ElementMatchers.isConstructor().and(ElementMatchers.hasDescriptor(descriptor));
        }else {
            elementMatcher = ElementMatchers.isMethod().and(ElementMatchers.named(methodName)).and(ElementMatchers.hasDescriptor(descriptor));
        }
        System.out.println(hookRule);
//        return Advice.to(SourceAdvice.class).on(elementMatcher);
        if (hookRule.getType().equals("source")) {
            return Advice.to(SourceAdvice.class).on(elementMatcher);
        } else if (hookRule.getType().equals("propagator")) {
            return Advice.to(PropagatorAdvice.class).on(elementMatcher);
        } else {
            return Advice.to(SinkAdvice.class).on(elementMatcher);
        }
    }
}
