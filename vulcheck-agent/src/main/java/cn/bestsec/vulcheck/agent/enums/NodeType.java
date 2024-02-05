package cn.bestsec.vulcheck.agent.enums;

/**
 * 节点类型枚举
 * @author hjx
 * @since 2024/1/12
 */
public enum NodeType {
    ENTRY("http", 1),
    SOURCE("source", 2),
    PROPAGATOR("propagator", 3),
    SINK("sink", 4),
    SANITIZER("sanitizer", 5);
    private String name;
    private int index;
    NodeType(String name, int index){
        this.name = name;
        this.index = index;
    }

    public String getName() {
        return this.name;
    }

    public int getIndex() {
        return this.index;
    }

    public static NodeType getByName(String name) {
        for (NodeType nodeType: NodeType.values()) {
            if (nodeType.getName().equals(name)) {
                return nodeType;
            }
        }
        return null;
    }

    public static NodeType getByIndex(int index) {
        for (NodeType nodeType : NodeType.values()) {
            if (nodeType.getIndex() == index) {
                return nodeType;
            }
        }
        return null;
    }
}
