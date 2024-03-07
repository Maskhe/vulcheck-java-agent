package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.agent.trace.TracingContextManager;
import cn.bestsec.vulcheck.agent.utils.GsonUtils;
import cn.bestsec.vulcheck.spy.DispatcherHandler;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * VulCheck上下文，单例对象，存储着污点池、hook规则等关键信息供漏洞检测时使用
 * @author tntaxin
 * @since 2023/11/17
 */
@Data
public class VulCheckContext {
    private HashMap<String, ArrayList<HookRule>> hookRules;
    private HashMap<String, HookRule> matchedHookNodes;
    private InheritableThreadLocal<HashSet<Object>> taintPool;
    private TracingContextManager tracingContextManager;
    private boolean debug = false;
    public AtomicInteger entryDepth = new AtomicInteger(0);
    private boolean exitEntry;
    public ThreadLocal<Integer> agentDepth = new ThreadLocal();
    public int sinkDepth = 0;
    public AtomicInteger propagatorDepth = new AtomicInteger(0);
    public int sourceDepth = 0;
    public int filterDepth = 0;

    private VulCheckContext(HashMap<String, ArrayList<HookRule>> hookRules){
        this.hookRules = hookRules;
        this.taintPool = new InheritableThreadLocal<>();
        this.taintPool.set(new HashSet<Object>());
        agentDepth.set(0);
        DispatcherHandler.setDispatcher(new DispatcherImpl(this));
        this.matchedHookNodes = new HashMap<>();
        this.tracingContextManager = new TracingContextManager();
    }

    private static class VulCheckContextHolder{
        private static HashMap<String, ArrayList<HookRule>> getHookRules(){
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

            return GsonUtils.fromJson(json, new TypeToken<HashMap<String, List<HookRule>>>(){}.getType());
        }
        private static final VulCheckContext INSTANCE = new VulCheckContext(getHookRules());
    }

    public static VulCheckContext newInstance(){
        return VulCheckContextHolder.INSTANCE;
    }

    public void addMatchedHookNode(String methodName, HookRule hookRule){
        this.matchedHookNodes.put(methodName, hookRule);
    }

    public boolean isEnterAgent() {
        return this.agentDepth.get() > 0;
    }
    public void enterAgent() {
        this.agentDepth.set(this.agentDepth.get() + 1);
//        this.agentDepth.incrementAndGet();
    }

    public void leaveAgent() {
        this.agentDepth.set(this.agentDepth.get()-1);
    }

    public boolean isValidSink() {
        return this.entryDepth.get() > 0 && this.sourceDepth == 0 && this.sinkDepth == 1;
    }

    public boolean isValidPropagator() {
        return this.entryDepth.get() > 0 && this.sourceDepth == 0 && this.sinkDepth == 0 && this.agentDepth.get() == 0;
    }

    public boolean isValidSource() {
        return this.entryDepth.get() >0  && this.sourceDepth == 1 && Objects.equals(this.propagatorDepth.get(), 0) && this.sinkDepth == 0;
    }

    public void setDebug(boolean debug) {
        this.debug = debug;
    }

    public boolean isDebug() {
        return this.debug;
    }
}
