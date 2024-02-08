package cn.bestsec.vulcheck.agent.trace;

/**
 * 管理TracingContext的生命周期
 */
public class TracingContextManager {
    private static final InheritableThreadLocal<TracingContext> context = new InheritableThreadLocal<>();

    /**
     * 获取单例TracingContext对象
     * @return TracingContext
     */
    public static TracingContext getContext() {
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
    public static void destoryContext() {
        context.remove();
    }
}
