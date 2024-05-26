package cn.bestsec.vulcheck.agent.trace.http;

import lombok.Data;

import java.util.Map;

@Data
public class HttpResponse {
    private int status;
    private Map<String, String> headers;
    private String body;

    public String toString() {
        StringBuilder headers = new StringBuilder();
        for (Map.Entry<String, String> entry : this.headers.entrySet()) {
            String header = entry.getKey() + ": " + entry.getValue();
            headers.append(header).append("\r\n");
        }
        return String.format("%s %s \n\n%s\r\n%s", "HTTP/1.1", this.status,
                headers, this.body);
    }
}
