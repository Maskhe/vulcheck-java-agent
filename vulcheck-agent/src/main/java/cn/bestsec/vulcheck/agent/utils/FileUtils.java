package cn.bestsec.vulcheck.agent.utils;

import cn.bestsec.vulcheck.agent.VulCheckAgent;
import org.tinylog.Logger;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class FileUtils {
    public static void extractJars(String targetPath){
        String spyJarName = "vulcheck-spy.jar";
        try (InputStream inputStream = VulCheckAgent.class.getClassLoader().getResourceAsStream(spyJarName)) {
            if (inputStream != null) {
                File spyFile = new File(targetPath);
                if (!spyFile.getParentFile().exists()) {
                    Logger.debug(String.format("创建目录%s成功", spyFile.getParentFile()));
                    if (!spyFile.getParentFile().mkdirs()) {
                        Logger.debug("创建目录" + spyFile.getParentFile() + "失败");
                    }
                }
                FileOutputStream fos = new FileOutputStream(spyFile);
                byte[] bytes = new byte[1024];
                int bytesRead;
                while ((bytesRead = inputStream.read(bytes)) != -1) {
                    fos.write(bytes, 0, bytesRead);
                }
                fos.close();
            }
            Logger.info(String.format("成功提取jar文件到%s", targetPath));
        } catch (IOException e) {
            Logger.error(String.format("提取vulcheck-spy.jar到%s失败！", targetPath));
        }
    }

}
