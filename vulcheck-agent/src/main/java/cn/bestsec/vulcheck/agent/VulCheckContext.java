package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.spy.DispatcherHandler;
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
    private HashMap<String, ArrayList<HookRule>> hookRules;
    private HashMap<String, HookRule> matchedHookPoints;
    private ThreadLocal<HashSet<Object>> taintPool;
    private VulCheckContext(HashMap<String, ArrayList<HookRule>> hookRules){
        this.hookRules = hookRules;
        this.taintPool = ThreadLocal.withInitial(HashSet::new);
        DispatcherHandler.setDispatcher(new DispatcherImpl());
        this.matchedHookPoints = new HashMap<>();
    }

    private static class VulCheckContextHolder{
        private static HashMap<String, ArrayList<HookRule>> getHookRules(){
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
            return hookRules;
        }
        private static final VulCheckContext INSTANCE = new VulCheckContext(getHookRules());
    }

    public static VulCheckContext newInstance(){
        return VulCheckContextHolder.INSTANCE;
    }

    public void addMatchedHookPoint(String methodName, HookRule hookRule){
        this.matchedHookPoints.put(methodName, hookRule);
    }
}
