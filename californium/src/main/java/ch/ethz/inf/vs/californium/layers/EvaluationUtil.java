package ch.ethz.inf.vs.californium.layers;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;


public class EvaluationUtil {
	
	public static long getCpuTime() {
	    ThreadMXBean bean = ManagementFactory.getThreadMXBean( );
	    return bean.getCurrentThreadCpuTime();
	}
	 
	/** Get user time in nanoseconds. */
	public static long getUserTime( ) {
	    ThreadMXBean bean = ManagementFactory.getThreadMXBean();
	    return bean.getCurrentThreadUserTime();
	}

	/** Get system time in nanoseconds. */
	public static long getSystemTime( ) {
	    ThreadMXBean bean = ManagementFactory.getThreadMXBean( );
	    return (bean.getCurrentThreadCpuTime() - bean.getCurrentThreadUserTime( ));
	}
	
	public static long getCpuTime(long threadId) {
	    ThreadMXBean bean = ManagementFactory.getThreadMXBean( );
	    return bean.getThreadCpuTime(threadId);
	}
	 
	/** Get user time in nanoseconds. */
	public static long getUserTime(long threadId ) {
	    ThreadMXBean bean = ManagementFactory.getThreadMXBean();
	    return bean.getThreadUserTime(threadId);
	}

	/** Get system time in nanoseconds. */
	public static long getSystemTime(long threadId) {
	    ThreadMXBean bean = ManagementFactory.getThreadMXBean( );
	    return (bean.getThreadCpuTime(threadId) - bean.getThreadUserTime(threadId));
	}
}
