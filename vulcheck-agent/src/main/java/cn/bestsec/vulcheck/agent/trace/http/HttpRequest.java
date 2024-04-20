package cn.bestsec.vulcheck.agent.trace.http;

import lombok.Data;

import java.util.Map;

@Data
public class HttpRequest {
    private String method;
    private String serverName;
    private int serverPort;
    private String scheme;
    private String protocol;
    private String uri;
    private String query;
    private Map<String, String> headers;
    private String body;

    public String toString() {
        StringBuilder headers = new StringBuilder();
        for (Map.Entry<String, String> entry : this.headers.entrySet()) {
            String header = entry.getKey() + ": " + entry.getValue();
            headers.append(header).append("\r\n");
        }
        return String.format("%s %s %s\r\n%s\r\n%s", this.method, this.uri+"?"+this.query, this.protocol,
                headers, this.body);
    }
}
