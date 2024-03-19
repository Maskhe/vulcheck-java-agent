package cn.bestsec.vulcheck.agent.trace;

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
    public String context2Json() {}

    // 把json格式的context打入队列，供worker异步消费
    public void reportContext(){}
}
