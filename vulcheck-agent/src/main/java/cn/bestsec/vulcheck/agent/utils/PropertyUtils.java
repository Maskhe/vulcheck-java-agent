package cn.bestsec.vulcheck.agent.utils;

public class PropertyUtils {
    private final static String PROJECT_NAME = "projectName";
    public static String getProjectName() {
        return System.getProperty(PROJECT_NAME);
    }
}
