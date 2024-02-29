package cn.bestsec.vulcheck.agent.enums;

/**
 * 继承类型枚举
 * @author hjx
 * @since 2024/1/12
 */
public enum InheritTypeEnum {
    ALL("ALL"),
    SUBCLASSES("SUBCLASSES"),
    NONE("NONE");
    private final String name;

    InheritTypeEnum(String name) {
        this.name = name;
    }

    public  static InheritTypeEnum getTypeByName(String name){
        for (InheritTypeEnum inheritTypeEnum : InheritTypeEnum.values()) {
            if (inheritTypeEnum.name.equals(name)) {
                return inheritTypeEnum;
            }
        }
        return null;
    }

    public String getName(){
        return this.name;
    }
}
