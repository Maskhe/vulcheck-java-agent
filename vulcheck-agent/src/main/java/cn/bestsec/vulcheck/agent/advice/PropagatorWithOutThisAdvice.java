package cn.bestsec.vulcheck.agent.advice;

import cn.bestsec.vulcheck.spy.Dispatcher;
import cn.bestsec.vulcheck.spy.DispatcherHandler;
import net.bytebuddy.asm.Advice;


public class PropagatorWithOutThisAdvice {
    @Advice.OnMethodEnter
    public static void enter(@Advice.AllArguments Object[] args){
//        System.out.println("进入传播节点");
        Dispatcher dispatcher = DispatcherHandler.getDispatcher();
        dispatcher.enterPropagatorWithoutThis(args);
    }
}
