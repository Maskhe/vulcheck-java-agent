package cn.bestsec.vulcheck.spy;

import net.bytebuddy.description.method.MethodDescription;

import java.lang.reflect.Executable;

public interface Dispatcher {
    void enterSource();
    void enterPropagator();

    void enterSink(Class<?> cls, Object caller, Executable executable, Object[] args, Object ret);

    void exitSource(Class<?> cls, Object caller, Executable executable, Object[] args, String ret);
    void exitPropagator(Class<?> cls, Object caller, Executable executable, Object[] args, Object ret);

    void exitPropagatorWithNoRet(Class<?> cls, Object caller, Executable executable, Object[] args);
    void exitSink();
}
