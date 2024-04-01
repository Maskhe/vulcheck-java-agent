package cn.bestsec.vulcheck.agent.enums;

/**
 * 节点类型枚举
 * @author hjx
 * @since 2024/1/12
 */
public enum NodeTypeEnum {
    ENTRY("ENTRY", 1),
    SOURCE("SOURCE", 2),
    PROPAGATOR("PROPAGATOR", 3),
    SINK("SINK", 4),
    SANITIZER("SANITIZER", 5);
    private String name;
    private int index;
    NodeTypeEnum(String name, int index){
        this.name = name;
        this.index = index;
    }

    public String getName() {
        return this.name;
    }

    public int getIndex() {
        return this.index;
    }

    public static NodeTypeEnum getByName(String name) {
        for (NodeTypeEnum nodeType: NodeTypeEnum.values()) {
            if (nodeType.getName().equalsIgnoreCase(name)) {
                return nodeType;
            }
        }
        return null;
    }

    public static NodeTypeEnum getByIndex(int index) {
        for (NodeTypeEnum nodeType : NodeTypeEnum.values()) {
            if (nodeType.getIndex() == index) {
                return nodeType;
            }
        }
        return null;
    }
}
