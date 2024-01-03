package cn.bestsec.vulcheck.agent.enums;

public enum NodeType {
    HTTP("http"),
    SOURCE("source"),
    PROPAGATOR("propagator"),
    SINK("sink");
    private String name;
    NodeType(String name){
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    public static NodeType getByName(String name) {
        for (NodeType nodeType: NodeType.values()) {
            if (nodeType.getName().equals(name)) {
                return nodeType;
            }
        }
        return null;
    }
}
