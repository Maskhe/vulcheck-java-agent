package cn.bestsec.vulcheck.spy;

import net.bytebuddy.description.method.MethodDescription;

import java.lang.reflect.Executable;
import java.lang.reflect.Method;


/**
 * 分发器接口，存储着javaagent对不同类型节点的hook处理逻辑
 * @author tntaxin
 * @since 2023/11/20
 */
public interface Dispatcher {
    void enterEntry();
    void exitEntry();
    void enterSource();
    void enterPropagator(Object caller, Object thisObject);

    /**
     * 进入无返回值的propagator节点时的增强代码
     */
    void enterPropagatorWithNoRet(Class<?> cls, Object caller, Executable executable, Object[] args);

    void enterPropagatorWithoutThis(Object[] args);

    void enterSink(Class<?> cls, Object caller, Executable executable, Object[] args);

    /**
     *  退出source节点前的处理逻辑
     * @param cls
     * @param caller
     * @param executable
     * @param args
     * @param ret
     */
    void exitSource(Class<?> cls, Object caller, Executable executable, Object[] args, Object ret);

    /**
     * 有返回值的传播节点处理逻辑
     * @param cls
     * @param caller
     * @param executable
     * @param args
     * @param ret
     */
    void exitPropagator(Class<?> cls, Object caller, Executable executable, Object[] args, Object ret, Object thisObject);

    /**
     * 无返回值的传播节点处理逻辑
     * @param cls 当用当前方法的对象所属的类
     * @param caller 调用当前方法的对象
     * @param executable 当前方法
     * @param args 当前方法所有的入参
     */
    void exitPropagatorWithNoRet(Class<?> cls, Object caller, Executable executable, Object[] args);

    /**
     *
     */
    void exitSink();

    /**
     * 进入agent执行范围
     */
    void enterAgent();

    /**
     * 离开Agent执行范围
     */
    void leaveAgent();

    boolean isEnterAgent();

    void test();
}
