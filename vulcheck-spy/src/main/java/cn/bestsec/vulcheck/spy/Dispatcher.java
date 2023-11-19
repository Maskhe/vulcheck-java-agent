package cn.bestsec.vulcheck.spy;

import net.bytebuddy.description.method.MethodDescription;

import java.lang.reflect.Executable;

public interface Dispatcher {
    void enterSource();
    void enterPropagator();

    void enterSink(Class<?> cls, Executable executable, Object[] objs, Object o);

    void exitSource(Class<?> cls, Executable executable, Object[] objs, String ret);
    void exitPropagator(Class<?> cls, Executable executable, Object[] objs, Object ret);
    void exitSink();
}
