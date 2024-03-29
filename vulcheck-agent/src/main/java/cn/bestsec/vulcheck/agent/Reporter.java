package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.agent.trace.TracingContext;
import org.tinylog.Logger;

public class Reporter implements Runnable{
    VulCheckContext vulCheckContext = VulCheckContext.newInstance();
    TracingContext tracingContext = vulCheckContext.getTracingContextManager().getContext();

    @Override
    public void run() {
        tracingContext.enterAgent(); // 进入agent执行范围
        if (vulCheckContext.getSegmentQueue().isEmpty()) {
            return;
        }
        String segmentJson = vulCheckContext.getSegmentQueue().poll();
        Logger.info(segmentJson);
        tracingContext.exitAgent();  // 退出agent执行范围
    }
}
