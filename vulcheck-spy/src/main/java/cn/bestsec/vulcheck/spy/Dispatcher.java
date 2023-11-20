package cn.bestsec.vulcheck.spy;

import net.bytebuddy.description.method.MethodDescription;

import java.lang.reflect.Executable;

public interface Dispatcher {
    void enterSource();
    void enterPropagator();

    void enterSink(Class<?> cls, Object caller, Executable executable, Object[] args);

    /**
     *  退出source节点前的处理逻辑
     * @param cls
     * @param caller
     * @param executable
     * @param args
     * @param ret
     */
    void exitSource(Class<?> cls, Object caller, Executable executable, Object[] args, String ret);

    /**
     * 有返回值的传播节点处理逻辑
     * @param cls
     * @param caller
     * @param executable
     * @param args
     * @param ret
     */
    void exitPropagator(Class<?> cls, Object caller, Executable executable, Object[] args, Object ret);

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
}
