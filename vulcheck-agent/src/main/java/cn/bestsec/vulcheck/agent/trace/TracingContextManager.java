package cn.bestsec.vulcheck.agent.trace;

import cn.bestsec.vulcheck.agent.utils.GsonUtils;

/**
 * 管理TracingContext的生命周期
 */
public class TracingContextManager {
    private final InheritableThreadLocal<TracingContext> context = new InheritableThreadLocal<>();

    /**
     * 获取单例TracingContext对象
     * @return TracingContext
     */
    public  TracingContext getContext() {
        if(context.get() == null) {
            Segment segment = new Segment("");
            TracingContext tracingContext = new TracingContext(segment);
            context.set(tracingContext);
        }
        return context.get();
    }

    /**
     * 销毁TracingContext对象
     */
    public void destoryContext() {
        context.remove();
    }

    // 把context转换为json格式
    public String context2Json() {
        return GsonUtils.toJson(this.getContext());
    }

    // 把json格式的context打入队列，供worker异步消费
    public void reportContext(){}
}
