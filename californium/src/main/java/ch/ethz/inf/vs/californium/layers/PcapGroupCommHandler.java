
package ch.ethz.inf.vs.californium.layers;

import java.io.FileWriter;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Udp;


import com.csvreader.CsvWriter;

import ch.ethz.inf.vs.californium.coap.EndpointAddress;
import ch.ethz.inf.vs.californium.coap.Message;
import ch.ethz.inf.vs.californium.layers.MulticastUDPLayer.REQUEST_TYPE;

public class PcapGroupCommHandler<String> extends AbstractLayer implements
		PcapPacketHandler<String> {
	private int port = 5683;
	private static final Logger log = Logger.getLogger(PcapGroupCommHandler.class.getName());
	
	// limit to 5 concurrent requests
	private ExecutorService executor = Executors.newFixedThreadPool(5);
			
	private final HashSet<Thread> workerThreads = new HashSet<Thread>();
		
	private CsvWriter perfLog;
		
	private volatile int numRequest = 0;

	public PcapGroupCommHandler(int port) {
		if(port != 0)
			this.port = port;
		
		try {
			perfLog = new CsvWriter(new FileWriter("./coap_gc_perf_log.csv", false), ';');
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void nextPacket(PcapPacket packet, String user) {
		
		if(packet.getHeaderCount() == 1){ // indication for tunnel packet
			log.info("Packet received through PCAP (tunnel packet).");
			// the payload might be directly an ipv6 packet
			if(packet.getByte(0) >> 4 == 6 && packet.size() > 48){ // ipv6 version, at least ipv6 and udp header
				byte[] srcAddressByte = new byte[16];
				packet.getByteArray(8, srcAddressByte);
				byte[] destAddress = new byte[16];
				byte[] payload = new byte[packet.size() - 48]; // everything beside IPv6 and UDP header
				packet.getByteArray(24, destAddress);
				try {
					Inet6Address srcIpv6 = (Inet6Address) Inet6Address.getByAddress(srcAddressByte);
					Inet6Address destIpv6 = (Inet6Address) Inet6Address.getByAddress(destAddress);
					// extract udp header (4 byte)
					byte[] destPortBytes = new byte[2];
					packet.getByteArray(42
							, destPortBytes);
					
					byte[] srcPortBytes = new byte[2];
					packet.getByteArray(40
							, destPortBytes);
			
					Integer srcPort = srcPortBytes[0] * 256 + srcPortBytes[1];
					Integer destPort = destPortBytes[0] * 256 + destPortBytes[1];
					
					packet.getByteArray(48, payload);
					
					if (destPort == this.port && destIpv6.isMulticastAddress()) 
					{
						numRequest++;
						log.info("Received multicast message through PCAP (over tunnel adapter)s.");
						RequestReceiver recv = new RequestReceiver(destIpv6, srcIpv6, srcPort, payload);
						executor.execute(recv);
						if(numRequest == 1000){
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
							
						
							try {
								perfLog.writeRecord( new java.lang.String[]{"" + totalCPUTime,"" + numRequest, "" + cpuTimePerRequest});
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
							executor.shutdown();
							perfLog.close();
						}
					}
											
				} catch (UnknownHostException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		
		if (packet.hasHeader(Udp.ID) && packet.hasHeader(Ip6.ID)) {
			Ip6 ipv6 = packet.getHeader(new Ip6());
			Udp udp = packet.getHeader(new Udp());
			byte[] destination = ipv6.destination();
			Inet6Address dest = null;
			Inet6Address src = null;
			try {
				dest = (Inet6Address) InetAddress.getByAddress(destination);
				src = (Inet6Address) InetAddress.getByAddress(ipv6.source());
			} catch (UnknownHostException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			if (udp.destination() == this.port && dest.isMulticastAddress()) 
				{
					log.info("Received multicast message through PCAP.");
					RequestReceiver recv = new RequestReceiver(dest, src, udp.source(), udp.getPayload());
					recv.start();
				}
			
		}
	}

	// each request spans off as a new thread
	// required for the request identification using
	// thread context variables
	class RequestReceiver extends Thread {
		private Inet6Address groupAddress;
		private Inet6Address src;
		private int srcPort;
		private byte[] payload;

		public RequestReceiver(Inet6Address groupAddress, Inet6Address src,  int srcPort, byte[] payload) {
			this.groupAddress = groupAddress;
			this.payload = payload;
			this.src = src;
			this.srcPort = srcPort;

		}

		public void run() {
			MulticastUDPLayer.setMulticastAddress(groupAddress);
			MulticastUDPLayer.setRequestType(REQUEST_TYPE.MULTICAST_REQUEST);

			// get current time
			long timestamp = System.nanoTime();

			// extract message data from datagram
			

			// create new message from the received data
			Message msg = Message.fromByteArray(payload);

			if (msg != null) {
				msg.setNetworkInterface(groupAddress);

				// remember when this message was received
				msg.setTimestamp(timestamp);

				msg.setPeerAddress(new EndpointAddress(src,
						srcPort));

				// protect against unknown exceptions
				try {
					receiveMessage(msg);

				} catch (Exception e) {
					e.printStackTrace();
				}
			} else {
				log.severe("Illeagal datagram received");
			}

		}
	}

	@Override
	protected void doSendMessage(Message msg) throws IOException {
		// here we only recevie messages - COAP PUT NON

	}

	@Override
	protected void doReceiveMessage(Message msg) {
		deliverMessage(msg);
	}
}
