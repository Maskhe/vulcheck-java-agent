package cn.bestsec.vulcheck.spy;

public class DispatcherHandler {
    private static Dispatcher dispatcher;
    public static void setDispatcher(Dispatcher dispathcerImpl){
        dispatcher = dispathcerImpl;
    }

    public static Dispatcher getDispatcher(){
        return dispatcher;
    }

}
