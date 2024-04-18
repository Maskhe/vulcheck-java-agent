package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.agent.enums.AgentState;
import cn.bestsec.vulcheck.agent.rule.HookRule;
import cn.bestsec.vulcheck.agent.trace.TracingContextManager;
import cn.bestsec.vulcheck.agent.utils.GsonUtils;
import cn.bestsec.vulcheck.agent.utils.HttpUtils;
import cn.bestsec.vulcheck.spy.DispatcherHandler;
import com.google.gson.reflect.TypeToken;
import lombok.Data;

import java.util.*;

/**
 * VulCheck上下文，单例对象，存储着污点池、hook规则等关键信息供漏洞检测时使用
 * @author tntaxin
 * @since 2023/11/17
 */
@Data
public class VulCheckContext {
    private HashMap<String, ArrayList<HookRule>> hookRules;
    private HashMap<String, HookRule> matchedHookNodes;
    private TracingContextManager tracingContextManager;
    private Queue<String> segmentQueue;
    private AgentState agentState;

    private VulCheckContext(HashMap<String, ArrayList<HookRule>> hookRules){
        this.hookRules = hookRules;
        this.tracingContextManager = new TracingContextManager();
        this.segmentQueue = new LinkedList<>();
        DispatcherHandler.setDispatcher(new DispatcherImpl(this));
        this.matchedHookNodes = new HashMap<>();
        if (this.hookRules.isEmpty()) {
            this.agentState = AgentState.START_FAILED;
        } else {
            this.agentState = AgentState.STARTING;
        }
    }

    private static class VulCheckContextHolder{
        private static HashMap<String, ArrayList<HookRule>> getHookRules(){
            // 读取服务端hook规则
            String json = "";
            String response = HttpUtils.sendGetRequest("http://localhost:8000/hookrulesmanage/?inUse=1");
            if (response == null || response.contains("Error")) {
                return new HashMap<>();
            }
            json = response;
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

    public void report(String segment) {
        this.segmentQueue.offer(segment);
        Thread reporter = new Thread(new Reporter());
        reporter.start();
    }

    public String toString() {
        return "vulcheckcontext";
    }
}
