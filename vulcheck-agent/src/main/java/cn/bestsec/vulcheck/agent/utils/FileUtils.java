package cn.bestsec.vulcheck.agent.utils;

import cn.bestsec.vulcheck.agent.VulCheckAgent;
import org.tinylog.Logger;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class FileUtils {
    public static void extractJars(String targetPath){
        String spyJarName = "vulcheck-spy.jar";
        try (InputStream inputStream = VulCheckAgent.class.getClassLoader().getResourceAsStream(spyJarName)) {
            if (inputStream != null) {
                FileOutputStream fos = new FileOutputStream(targetPath);
                byte[] bytes = new byte[1024];
                int bytesRead;
                while ((bytesRead = inputStream.read(bytes)) != -1) {
                    fos.write(bytes, 0, bytesRead);
                }
                fos.close();
            }
            Logger.info(String.format("成功提取jar文件%s", targetPath));
        } catch (IOException e) {
            Logger.error(String.format("提取vulcheck-spy.jar到%s失败！", targetPath));
        }
    }

}
