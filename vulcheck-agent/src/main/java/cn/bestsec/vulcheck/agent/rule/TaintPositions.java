package cn.bestsec.vulcheck.agent.rule;

import cn.bestsec.vulcheck.agent.rule.TaintPosition;
import lombok.Data;

import java.util.ArrayList;

/**
 * 该类用于描述一次方法调用中涉及到的多个污点来源位置或多个污点目标位置之间的关系
 * @author hjx
 * @since 2024/2/22
 */
@Data
public class TaintPositions {
    private String relation;
    private ArrayList<TaintPosition> positions;

    public TaintPositions() {
        this.relation = "AND";
        this.positions = new ArrayList<>();
    }
    public TaintPositions(String relation) {
        this.relation = relation;
        this.positions = new ArrayList<>();
    }

    public void addPosition(TaintPosition taintPosition) {
        this.positions.add(taintPosition);
    }
}
