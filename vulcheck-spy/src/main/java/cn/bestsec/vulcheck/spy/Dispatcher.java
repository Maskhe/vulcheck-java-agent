package cn.bestsec.vulcheck.spy;

import java.lang.reflect.Executable;

public interface Dispatcher {
    void enterSource();
    void enterPropagator();

    void enterSink();

    void exitSource(Class<?> cls, Executable executable, Object[] objs, String ret);
    void exitPropagator();
    void exitSink();
}
