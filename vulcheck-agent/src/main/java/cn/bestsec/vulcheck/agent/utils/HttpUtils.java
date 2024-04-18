package cn.bestsec.vulcheck.agent.utils;

import org.tinylog.Logger;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * HTTP工具类
 * @author hjx
 * @since 2024/4/18
 */
public class HttpUtils {

    /**
     * 处理响应
     * @param conn HttpURLConnection
     * @return http响应信息
     */
    private static String handleResponse(HttpURLConnection conn) {
        try {
            int statusCode = conn.getResponseCode();
            String statusMessage = conn.getResponseMessage();
            if (statusCode == HttpURLConnection.HTTP_OK || statusCode == HttpURLConnection.HTTP_CREATED) {
                BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    response.append(line);
                }
                br.close();
                return response.toString();
            } else {
                return "Error: " + statusCode + " - " + statusMessage;
            }
        } catch (Exception e) {
            Logger.error(e.getMessage());
            return null;
        }
    }

    public static String sendPostRequest(String urlString, String postData) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlString);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

            OutputStream os = conn.getOutputStream();
            os.write(postData.getBytes());
            os.flush();

            return handleResponse(conn);

        } catch (Exception e) {
            Logger.error(e.getMessage());
            return null;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    public static String sendGetRequest(String urlString) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlString);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            return handleResponse(conn);

        } catch (Exception e) {
            Logger.error(e.getMessage());
            return null;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }
}

