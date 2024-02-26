package cn.bestsec.vulcheck.agent;


import cn.bestsec.vulcheck.agent.enums.PositionTypeEnum;
import lombok.Data;

/**
 * 污点位置类，用来表示一次方法调用中的污点来源及污点目标
 * @author hjx
 * @since 2024/2/22
 */
@Data
public class TaintPosition {
    private PositionTypeEnum positionType;
    private int index;
    private String badValueRegex;
    private boolean tracked;
}
