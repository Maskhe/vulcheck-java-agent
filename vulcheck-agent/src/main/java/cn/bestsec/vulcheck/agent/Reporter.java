package cn.bestsec.vulcheck.agent;

import cn.bestsec.vulcheck.agent.trace.TracingContext;
import cn.bestsec.vulcheck.agent.utils.HttpUtils;
import org.tinylog.Logger;

import java.io.BufferedWriter;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * 上报方法池到服务端
 * @author hjx
 * @since 2024/4/18
 */
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
        Logger.debug(segmentJson);
        try {
            String body = "span_pool=" + segmentJson;
            String response = HttpUtils.sendPostRequest("http://localhost:8000/segment/", body);
            Logger.debug(response);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        tracingContext.exitAgent();  // 退出agent执行范围
    }
}
