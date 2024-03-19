//package cn.bestsec.vulcheck.agent.trace;
//
//import java.util.HashMap;
//
///**
// * 污点管理器
// */
//public class TaintManager {
//    TracingContext tracingContext;
//    public TaintManager(TracingContext tracingContext) {
//        this.tracingContext = tracingContext;
//    }
//
//
//    /**
//     * 创建污点
//     * @param obj 对象
//     * @return Taint
//     */
//    public Taint newTaint(Object obj) {
//        return new Taint(obj);
//    }
//
//    /**
//     * 当前对象是否命中污点池
//     * @param obj 对象
//     * @return boolean
//     */
//    public boolean isHitTaintPool(Object obj) {
//        HashMap<Integer, Taint> taintPool = this.tracingContext.getTaintPool();
//        return taintPool.containsKey(obj.hashCode());
//    }
//
//    /**
//     * 将污点放入污点池
//     * @param obj 对象
//     */
//    public void addTaint(Object obj) {
//        Taint taint = new Taint(obj);
//        int hash = taint.getHash();
//        HashMap<Integer, Taint> taintPool = this.tracingContext.getTaintPool();
//        if (taintPool.containsKey(hash)) {
//            return;
//        }
//        taintPool.put(hash, taint);
//    }
//}
