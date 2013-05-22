package ch.inf.vs.californium;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.StreamHandler;

import ch.inf.vs.californium.network.Endpoint;

/**
 * A server contains a resource structure and can listen to one or more
 * endpoints to handle requests. Resources of a server can send requests over
 * any endpoint the server is associated to.
 **/
public class Server implements ServerInterface {

	private final static Logger LOGGER = Logger.getLogger(Server.class.getName());
	
	private List<Endpoint> endpoints;
	
	private Resource root;
	
	private ScheduledExecutorService stackExecutor;
	private MessageDeliverer deliverer;
	
	public Server() {
		endpoints = new ArrayList<Endpoint>();
		stackExecutor = Executors.newScheduledThreadPool(4);
	}
	
	public Server(int... ports) {
		this();
		for (int port:ports)
			registerEndpoint(port);
	}
	
	public void start() {
		LOGGER.info("Start server");
		for (Endpoint ep:endpoints) {
			try {
				ep.start();
			} catch (Exception e) {
				e.printStackTrace();
				LOGGER.log(Level.WARNING, "Exception in thread \"" + Thread.currentThread().getName() + "\"", e);
			}
		}
	}
	
	public void stop() {
		LOGGER.info("Stop server");
		for (Endpoint ep:endpoints)
			ep.stop();
		stackExecutor.shutdown();
	}
	
	public void destroy() {
		LOGGER.info("Destroy server");
		for (Endpoint ep:endpoints)
			ep.destroy();
	}
	
	public void registerEndpoint(/*InetAddress, */ int port) {
		Endpoint endpoint = new Endpoint(port);
		addEndpoint(endpoint);
	}
	
	public void setMessageDeliverer(MessageDeliverer deliverer) {
		this.deliverer = deliverer;
		for (Endpoint endpoint:endpoints)
			endpoint.setMessageDeliverer(deliverer);
	}
	
	public void addEndpoint(Endpoint endpoint) {
		endpoint.setMessageDeliverer(deliverer);
		endpoint.setExecutor(stackExecutor);
		endpoints.add(endpoint);
	}
	
	public static void initializeLogger() {
//		// Run configuration VM: -Djava.util.logging.SimpleFormatter.format="[%1$tc] %4$s: %5$s (%2$s)%n"
//		try { 
//			LogManager.getLogManager().readConfiguration(new ByteArrayInputStream(
////				"java.util.logging.SimpleFormatter.format=[%1$tc] %4$s: %5$s (%2$s)%n" // with date and time
//				"java.util.logging.SimpleFormatter.format=%4$s: %5$s - (in %2$s)%n" // for debugging
//					.getBytes()));
//		} catch ( Exception e ) { e.printStackTrace(); }
//		Logger.getLogger("").addHandler(new StreamHandler(System.out, new SimpleFormatter()) {
//			@Override
//			public synchronized void publish(LogRecord record) {
//				super.publish(record);
//				super.flush();
//			}
//		});
		LogManager.getLogManager().reset();
		Logger logger = Logger.getLogger("");
		logger.addHandler(new StreamHandler(System.out, new Formatter() {
		    @Override
		    public synchronized String format(LogRecord record) {
		    	String stackTrace = "";
		    	Throwable throwable = record.getThrown();
		    	if (throwable != null) {
		    		StringWriter sw = new StringWriter();
		    		throwable.printStackTrace(new PrintWriter(sw));
		    		stackTrace = sw.toString();
		    	}
		    	
		        return String.format("%2d", record.getThreadID()) + " " + record.getLevel()+": "
		        		+ record.getMessage()
		        		+ " - ("+record.getSourceClassName()+".java:"+Thread.currentThread().getStackTrace()[8].getLineNumber()+") "
		                + record.getSourceMethodName()+"()"
		                + " in " + Thread.currentThread().getName()+"\n"
		                + stackTrace;
		    }
		}) {
			@Override
			public synchronized void publish(LogRecord record) {
				super.publish(record);
				super.flush();
			}
			}
		);
	}

	public Resource getRoot() {
		return root;
	}
}