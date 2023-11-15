package cn.bestsec.vulcheck.spy;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import lombok.Data;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;

/**
 * @author
 * @description
 * @since
 */

@Data
public class VulCheckContext {
    private HashMap<String, HookRule> hookRules;
    private ThreadLocal<HashSet<Object>> taintPool;
    private VulCheckContext(HashMap<String, HookRule> hookRules){
        this.hookRules = hookRules;
        this.taintPool = ThreadLocal.withInitial(HashSet::new);
    }

    private static class VulCheckContextHolder{
        private static HashMap<String, HookRule> getHookRules(){
            Gson gson = new Gson();
            // 读取服务端hook规则
            String json = "";
            URL uri = null;
            try {
                uri = new URL("http://localhost:8000/hookrulesmanage/?inUse=1");
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
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            HashMap<String, ArrayList<HookRule>> hookRules = gson.fromJson(json, new TypeToken<HashMap<String, List<HookRule>>>(){}.getType());
            HashMap<String, HookRule> res = new HashMap<>();
            for(Map.Entry<String, ArrayList<HookRule>> entry: hookRules.entrySet()){
                String className = entry.getKey();
                String uniqueMethod;
                for(HookRule hookRule: entry.getValue()){
                    uniqueMethod = className + "." + hookRule.getMethodName();
                    res.put(uniqueMethod, hookRule);
                }
            }
            return res;
        }
        private static final VulCheckContext INSTANCE = new VulCheckContext(getHookRules());
    }

    public static VulCheckContext newInstance(){
        return VulCheckContextHolder.INSTANCE;
    }

    public void addHookRule(String methodName, HookRule hookRule){
        this.hookRules.put(methodName, hookRule);
    }
}
