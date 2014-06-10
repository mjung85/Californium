package ch.ethz.inf.vs.californium.layers;

import java.io.FileWriter;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.SocketException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

import com.csvreader.CsvWriter;

import ch.ethz.inf.vs.californium.coap.EndpointAddress;
import ch.ethz.inf.vs.californium.coap.Message;
import ch.ethz.inf.vs.californium.coap.MessageReceiver;
import ch.ethz.inf.vs.californium.util.Properties;

public class MulticastUDPLayer extends AbstractLayer {

	private static final Logger log = Logger.getLogger(MulticastUDPLayer.class.getName());
	// Members
	// /////////////////////////////////////////////////////////////////////

	// The UDP socket used to send and receive datagrams
	// TODO Use MulticastSocket
	private MulticastSocket socket;

	// The thread that listens on the socket for incoming datagrams
	private ReceiverThread receiverThread;

	// explicitly bound server address
	private InetAddress inetAddress;

	private Inet6Address group;
	
	// limit to 5 concurrent requests
	private ExecutorService executor = Executors.newFixedThreadPool(5);
		
	private final HashSet<Thread> workerThreads = new HashSet<Thread>();
	
	private CsvWriter perfLog;
	
	private volatile int numRequest = 0;	

	private static ThreadLocal<REQUEST_TYPE> uniqueRequestType = new ThreadLocal<REQUEST_TYPE>() {
		@Override
		protected REQUEST_TYPE initialValue() {
			return REQUEST_TYPE.NORMAL_REQUEST;
		}

	};

	private static ThreadLocal<Inet6Address> multicastAddress = new ThreadLocal<Inet6Address>() {
		@Override
		protected Inet6Address initialValue() {
			return null;
		}

	};

	public synchronized static void setMulticastAddress(Inet6Address mAddr) {
		multicastAddress.set(mAddr);
	}

	public synchronized static Inet6Address getMulticastAddress() {
		return multicastAddress.get();
	}

	public synchronized static void setRequestType(REQUEST_TYPE reqType) {
		uniqueRequestType.set(reqType);
	}

	public synchronized static REQUEST_TYPE getRequestType() {
		return uniqueRequestType.get();
	}

	public enum REQUEST_TYPE {
		MULTICAST_REQUEST, NORMAL_REQUEST, LOCAL_REQUEST
	}

	// Inner Classes
	// ///////////////////////////////////////////////////////////////

	class ReceiverThread extends Thread {
		private volatile boolean stop = false;

		public ReceiverThread() {
			super("ReceiverThread");
		}

		@Override
		public void run() {
			synchronized(workerThreads){
				workerThreads.add(Thread.currentThread());
			}
			setMulticastAddress(MulticastUDPLayer.this.group);
			setRequestType(REQUEST_TYPE.MULTICAST_REQUEST);
			// always listen for incoming datagrams

			while (!stop) {

				// allocate buffer
				byte[] buffer = new byte[Properties.std
						.getInt("RX_BUFFER_SIZE") + 1]; // +1 to check for >
														// RX_BUFFER_SIZE

				// initialize new datagram
				DatagramPacket datagram = new DatagramPacket(buffer,
						buffer.length);

				// receive datagram
				try {
					socket.receive(datagram);
				} catch (IOException e) {
					log.severe("Could not receive datagram: " + e.getMessage());
					e.printStackTrace();
					continue;
				}

				// TODO: Dispatch to worker thread
				datagramReceived(datagram);
			}
		}

		public void stopReceiver() {
			stop = true;
			
			try {
				if(numRequest > 0){
					long totalCPUTime = 0;
					System.out.println("Shutdown called!");
					synchronized(workerThreads){
						System.out.println("There are " + workerThreads.size() + " worker threads.");
						for(Thread thread : workerThreads){				
							System.out.println("Thread ID: " + thread.getId() + ", " + 	EvaluationUtil.getCpuTime(thread.getId()));
							totalCPUTime += EvaluationUtil.getCpuTime(thread.getId());
						}
					}
					
					System.out.println("total CPU Time: " + totalCPUTime);
					double cpuTimePerRequest = ((double) totalCPUTime / numRequest) / 1000000; // nanoseconds to milliseconds 
					System.out.println("cpu time per request: " + cpuTimePerRequest + ", " + totalCPUTime / numRequest);						
	
					perfLog.writeRecord(new String[]{"" + totalCPUTime, "" + numRequest, "" + cpuTimePerRequest});
					executor.shutdown();
					perfLog.close();
				}
			} catch (IOException ioe) {
				ioe.printStackTrace();
			} 
		}
	}

	// Constructors
	// ////////////////////////////////////////////////////////////////

	/*
	 * Constructor for a new UDP layer
	 * 
	 * @param port The local UDP port to listen for incoming messages
	 * 
	 * @param daemon True if receiver thread should terminate with main thread
	 */
	public MulticastUDPLayer(int port, boolean daemon,
			Inet6Address ipv6MulticastAddress) throws SocketException {
		// initialize members

		try {
			perfLog = new CsvWriter(new FileWriter("./coap_perf_log.csv", false), ';');	
			// join IPv6 Multicast on all interfaces

			// List<InetSocketAddress> multicastSockets = new
			// ArrayList<InetSocketAddress>();

			InetSocketAddress socketAddress = new InetSocketAddress(group,
			 5683);
			this.group = ipv6MulticastAddress;

			this.socket = new MulticastSocket(null);					
			this.socket.setReuseAddress(true);
			this.socket.joinGroup(group);
			this.socket.bind(new InetSocketAddress(5684));

//			 Enumeration<NetworkInterface> networkInterfaces =
//			 NetworkInterface.getNetworkInterfaces();
//			 while(networkInterfaces.hasMoreElements()){
//			 NetworkInterface nextElement = networkInterfaces.nextElement();
//			 try{
//			 if(nextElement.isLoopback() && nextElement.isUp()) {
//				 LOG.info("Binding to"+nextElement.toString());
//				 this.socket.joinGroup(socketAddress, nextElement);
//			 }}
//			 catch(Exception e){
//			 // fail silently
//			 }
//			 }
		} catch (IOException e) {
			e.printStackTrace();
		}

		this.inetAddress = socket.getLocalAddress();
		this.receiverThread = new ReceiverThread();

		// decide if receiver thread terminates with main thread
		receiverThread.setDaemon(daemon);

		// start listening right from the beginning
		//this.receiverThread.start();
		executor.execute(receiverThread);

	}

	/*
	 * Constructor for a new UDP layer
	 */
	public MulticastUDPLayer() throws SocketException {
		this(0, true, null); // use any available port on the local host machine
	}

	public MulticastUDPLayer(Inet6Address ipv6MulticastAddress)
			throws SocketException {
		this(0, true, ipv6MulticastAddress);
	}

	// Commands
	// ////////////////////////////////////////////////////////////////////

	/*
	 * Decides if the listener thread persists after the main thread terminates
	 * 
	 * @param on True if the listener thread should stay alive after the main
	 * thread terminates. This is useful for e.g. server applications
	 */
	public void setDaemon(boolean on) {
		receiverThread.setDaemon(on);
	}

	// I/O implementation
	// //////////////////////////////////////////////////////////

	@Override
	protected void doSendMessage(Message msg) throws IOException {
		// sending response
		
		// retrieve payload
		byte[] payload = msg.toByteArray();

		// create datagram
		DatagramPacket datagram = new DatagramPacket(payload, payload.length,
				msg.getPeerAddress().getAddress(), msg.getPeerAddress()
						.getPort());

		// remember when this message was sent for the first time
		// set timestamp only once in order
		// to handle retransmissions correctly
		if (msg.getTimestamp() == -1) {
			msg.setTimestamp(System.nanoTime());
		}

		// send it over the UDP socket
		socket.send(datagram);
	}

	@Override
	protected void doReceiveMessage(Message msg) {
		System.out.println("$$$$$$$$ message received.");
		numRequest++;
		deliverMessage(msg);
	}

	// Internal
	// ////////////////////////////////////////////////////////////////////

	private void datagramReceived(DatagramPacket datagram) {
		// datagram received -> log starting time

		if (datagram.getLength() > 0) {

			// get current time
			long timestamp = System.nanoTime();

			// extract message data from datagram
			byte[] data = Arrays.copyOfRange(datagram.getData(),
					datagram.getOffset(), datagram.getLength());

			// create new message from the received data
			Message msg = Message.fromByteArray(data);

			if (msg != null) {
				msg.setNetworkInterface(inetAddress);

				// remember when this message was received
				msg.setTimestamp(timestamp);

				msg.setPeerAddress(new EndpointAddress(datagram.getAddress(),
						datagram.getPort()));

				if (datagram.getLength() > Properties.std
						.getInt("RX_BUFFER_SIZE")) {
					log.info(String
							.format("Marking large datagram for blockwise transfer: %s",
									msg.key()));
					msg.requiresBlockwise(true);
				}

				// protect against unknown exceptions
				try {

					receiveMessage(msg);

				} catch (Exception e) {
					StringBuilder builder = new StringBuilder();
					builder.append("Crash: ");
					builder.append(e.getMessage());
					builder.append('\n');
					builder.append("                    ");
					builder.append("Stacktrace for ");
					builder.append(e.getClass().getName());
					builder.append(":\n");
					for (StackTraceElement elem : e.getStackTrace()) {
						builder.append("                    ");
						builder.append(elem.getClassName());
						builder.append('.');
						builder.append(elem.getMethodName());
						builder.append('(');
						builder.append(elem.getFileName());
						builder.append(':');
						builder.append(elem.getLineNumber());
						builder.append(")\n");
					}

					log.severe(builder.toString());
				}
			} else {
				log.severe("Illeagal datagram received:\n" + data.toString());
			}

		} else {

			log.info(String.format("Dropped empty datagram from: %s:%d",
					datagram.getAddress().getHostName(), datagram.getPort()));
		}
	}

	// Queries
	// /////////////////////////////////////////////////////////////////////

	/*
	 * Checks whether the listener thread persists after the main thread
	 * terminates
	 * 
	 * @return True if the listener thread stays alive after the main thread
	 * terminates. This is useful for e.g. server applications
	 */
	public boolean isDaemon() {
		return receiverThread.isDaemon();
	}

	public int getPort() {
		return socket.getLocalPort();
	}

	public String getStats() {
		StringBuilder stats = new StringBuilder();

		stats.append("UDP port: ");
		stats.append(getPort());
		stats.append('\n');
		stats.append("Messages sent:     ");
		stats.append(numMessagesSent);
		stats.append('\n');
		stats.append("Messages received: ");
		stats.append(numMessagesReceived);

		return stats.toString();
	}

	public InetAddress getInetAddress() {
		return inetAddress;
	}

	public void close() {
		try {
			this.receiverThread.stopReceiver();

		} catch (Exception e) {
			e.printStackTrace();
		}
		try {
			this.socket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void receiveMessage(Message msg) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void registerReceiver(MessageReceiver receiver) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void sendMessage(Message msg) throws IOException {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void unregisterReceiver(MessageReceiver receiver) {
		// TODO Auto-generated method stub
		
	}
}
