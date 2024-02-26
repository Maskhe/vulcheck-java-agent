package cn.bestsec.vulcheck.agent.enums;

/**
 * @author hjx
 * @description
 * @since 2024/2/22
 */
public enum PositionTypeEnum {
    PARAM("参数"),
    RET("返回值"),
    CALLER("调用者");
    private String name;
    PositionTypeEnum(String name) {
        this.name = name;
    }

    public PositionTypeEnum getByName(String name) {
        for (PositionTypeEnum positionTypeEnum: PositionTypeEnum.values()) {
            if (positionTypeEnum.name.equals(name)) {
                return positionTypeEnum;
            }
        }
        return null;
    }
}
