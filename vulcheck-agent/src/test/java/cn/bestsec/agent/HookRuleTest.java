package cn.bestsec.agent;

import cn.bestsec.vulcheck.agent.HookRule;
import cn.bestsec.vulcheck.agent.HookRuleDeserializer;
import cn.bestsec.vulcheck.agent.utils.GsonUtils;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * @author
 * @description
 * @since
 */
public class HookRuleTest extends TestCase {
    public void testHookRuleDeserializer1() {
        String json = "{\"id\": 1, \"class_name\": \"org.springframework.web.method.support.HandlerMethodArgumentResolverComposite\", \"method_name\": \"resolveArgument\", \"descriptor\": \"(Lorg/springframework/core/MethodParameter;Lorg/springframework/web/method/support/ModelAndViewContainer;Lorg/springframework/web/context/request/NativeWebRequest;Lorg/springframework/web/bind/support/WebDataBinderFactory;)Ljava/lang/Object;\", \"rule_type\": \"ENTRY\", \"in_param\": \"\", \"out_param\": \"R\", \"inherit\": \"NONE\", \"in_use\": true, \"signature\": \"\", \"event_type\": \"spring\\u83b7\\u53d6\\u5165\\u53c2\", \"immune_vul_type\": \"\", \"tracked\": true}";
//        GsonBuilder gsonBuilder = new GsonBuilder();
//        HookRuleDeserializer hookRuleDeserializer = new HookRuleDeserializer();
//        gsonBuilder.registerTypeAdapter(HookRule.class, hookRuleDeserializer);
//        Gson gson = gsonBuilder.create();
//        HookRule hookRule = gson.fromJson(json, HookRule.class);
        HookRule hookRule = GsonUtils.fromJson(json, HookRule.class);
        System.out.println(hookRule);
        assertEquals(1,1);
    }

    public void testHookRuleDeserializer2() {
        String json = "{\"org.springframework.web.method.support.HandlerMethodArgumentResolverComposite\": [{\"id\": 1, \"class_name\": \"org.springframework.web.method.support.HandlerMethodArgumentResolverComposite\", \"method_name\": \"resolveArgument\", \"descriptor\": \"(Lorg/springframework/core/MethodParameter;Lorg/springframework/web/method/support/ModelAndViewContainer;Lorg/springframework/web/context/request/NativeWebRequest;Lorg/springframework/web/bind/support/WebDataBinderFactory;)Ljava/lang/Object;\", \"rule_type\": \"ENTRY\", \"in_param\": \"\", \"out_param\": \"R\", \"inherit\": \"NONE\", \"in_use\": true, \"signature\": \"\", \"event_type\": \"spring\\u83b7\\u53d6\\u5165\\u53c2\", \"immune_vul_type\": \"\", \"tracked\": true}]}";
        GsonBuilder gsonBuilder = new GsonBuilder();
        HookRuleDeserializer hookRuleDeserializer = new HookRuleDeserializer();
        gsonBuilder.registerTypeAdapter(HookRule.class, hookRuleDeserializer);
        Gson gson = gsonBuilder.create();
        HashMap<String, ArrayList<HookRule>> hookRule = gson.fromJson(json, new TypeToken<HashMap<String, List<HookRule>>>(){}.getType());
        System.out.println(hookRule);
        assertEquals(1,1);
    }
}
