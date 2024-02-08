package cn.bestsec.vulcheck.agent.trace;

import java.util.ArrayList;

/**
 * 用于存放污点经过的所有方法及当前请求相关信息
 */
public class Segment {
    private String segmentID = "0";
    /**
     * 存放方法
     */
    ArrayList<Span> spanPool = new ArrayList<>();
    /**
     * 本次请求对应的端点，http请求则是当前请求的url
     */
    String endpoint;

    public Segment(String endpoint) {
        this.endpoint = endpoint;
    }

    public void addSpan(Span method) {
        this.spanPool.add(method);
    }

    public String toJson() {
        return "json格式";
    }
}
