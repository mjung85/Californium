/*******************************************************************************
 * Copyright (c) 2012, Institute for Pervasive Computing, ETH Zurich.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * This file is part of the Californium (Cf) CoAP framework.
 ******************************************************************************/

package ch.ethz.inf.vs.californium.layers;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.logging.Logger;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

import ch.ethz.inf.vs.californium.coap.Message;
import ch.ethz.inf.vs.californium.util.Properties;

/**
 * UDP layer that is aware of multiple network interfaces
 * 
 * @author Markus Jung
 * 
 */
public class MultiInterfaceUDPLayer extends AbstractLayer {

	private static final Logger log = Logger
			.getLogger(MultiInterfaceUDPLayer.class.getName());

	private int port = 0;

	private Hashtable<InetAddress, UDPLayer> udplayers = new Hashtable<InetAddress, UDPLayer>();

	private UDPLayer defaultUDPLayer = null;

	// MulticastUDPLayer per group address
	private final Hashtable<Inet6Address, MulticastUDPLayer> multicastUDPLayers = new Hashtable<Inet6Address, MulticastUDPLayer>();

	public MultiInterfaceUDPLayer() throws SocketException {
		this(0, true);
	}

	private boolean PCAP_ENABLED = false;
	private boolean MCAST_ENABLED = false;
	private String PCAP_IF = "eth0";

	private Pcap pcap;
	private List<PcapIf> alldevs = new ArrayList<PcapIf>();
	private StringBuilder errbuf = new StringBuilder();

	public MultiInterfaceUDPLayer(final int port, boolean runAsDaemon)
			throws SocketException {
		this.port = port;

		PCAP_ENABLED = Boolean.parseBoolean(Properties.std.getProperty("iotsys.gateway.pcap", "false"));

		PCAP_IF = Properties.std.getProperty("iotsys.gateway.pcap.if", "eth0");
		MCAST_ENABLED = Boolean.parseBoolean(Properties.std.getProperty("iotsys.gateway.mcast", "true"));

		// for multicast group communication use
		// pcap or multicast datagram sockets
		// NOTE: in linux environments the mulicast mechanism
		// on data points does not work properly because
		// the target mulitcast address could not be
		// determined.
		if (MCAST_ENABLED) {
			if (PCAP_ENABLED) {
//				defaultUDPLayer = new UDPLayer(port, true);
//				defaultUDPLayer.registerReceiver(this);
				int r = Pcap.findAllDevs(alldevs, errbuf);
				if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
					log.info("No devs found");
					return;
				}

				int i = 0;
				int pick = 0;

				for (PcapIf device : alldevs) {
					String description = (device.getDescription() != null) ? device
							.getDescription() : "No description available.";
					log.info("" + (i++) + "#: " + device.getName() + " "
							+ description);
					if (device.getName().equals(PCAP_IF)) {
						pick = i - 1;
					}
				}

				log.info("openening device for pcap: "
						+ alldevs.get(pick).getName());
				PcapIf device = alldevs.get(pick);

				int snaplen = 64 * 1024;
				int flags = Pcap.MODE_PROMISCUOUS;
				int timeout = 10 * 1000;

				final Pcap pcap = Pcap.openLive(device.getName(), snaplen,
						flags, timeout, errbuf);

				if (pcap == null) {
					log.info("Cannot listen.");
				}
				
				final PcapGroupCommHandler<String> pcapGroupCommHandler = new PcapGroupCommHandler<String>(port, pcap);
				pcapGroupCommHandler.registerReceiver(this);
				log.info("Registered group comm handler.");

				Thread packetlistener = new Thread() {

					@Override
					public void run() {
						pcap.loop(0, pcapGroupCommHandler, "GroupCommListener");
					}

				};
				packetlistener.setDaemon(true);
				packetlistener.start();

			} else {
				try {
					Inet6Address group = (Inet6Address) Inet6Address
							.getByName("FF02:F::1");
					openMulticastSocket(group);
				} catch (UnknownHostException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}

			}
		}

		defaultUDPLayer = new UDPLayer();
		defaultUDPLayer.registerReceiver(this);

		Enumeration<NetworkInterface> networkInterfaces = NetworkInterface
				.getNetworkInterfaces();

		while (networkInterfaces.hasMoreElements()) {
			NetworkInterface iface = networkInterfaces.nextElement();

			Enumeration<InetAddress> inetAddresses = iface.getInetAddresses();
			for (InetAddress inetAddress : Collections.list(inetAddresses)) {

				try {
					UDPLayer udpLayer = new UDPLayer(inetAddress, port,
							runAsDaemon);
					udpLayer.registerReceiver(this);
					udplayers.put(inetAddress, udpLayer);
				} catch (Exception e) {
					// do nothing. may conflict with default UDP layer
				}
			}
		}
	}

	@Override
	protected void doSendMessage(Message msg) throws IOException {
		if (msg.getNetworkInterface() == null
				|| udplayers.get(msg.getNetworkInterface()) == null) {
			msg.setNetworkInterface(defaultUDPLayer.getInetAddress());
			defaultUDPLayer.sendMessage(msg);
		} else {

			udplayers.get(msg.getNetworkInterface()).sendMessage(msg);
		}
	}

	@Override
	protected void doReceiveMessage(Message msg) {
		
		deliverMessage(msg);
	}

	public int getPort() {
		return port;
	}

	public void openMulticastSocket(Inet6Address addr) throws SocketException {
		if (!PCAP_ENABLED && MCAST_ENABLED) {
			synchronized (multicastUDPLayers) {
				if (!multicastUDPLayers.contains(addr)) {
					MulticastUDPLayer multicastUDPLayer = new MulticastUDPLayer(
							addr);
					multicastUDPLayer.registerReceiver(this);

					multicastUDPLayers.put(addr, multicastUDPLayer);

				}
			}
		}
	}

	public void closeMulticastSocket(Inet6Address addr) throws SocketException {
		if (!PCAP_ENABLED && MCAST_ENABLED) {
			synchronized (multicastUDPLayers) {
				MulticastUDPLayer multicastUDPLayer = multicastUDPLayers
						.get(addr);
				if (multicastUDPLayer != null) {
					multicastUDPLayer.unregisterReceiver(this);
					multicastUDPLayer.close();
				}
			}
		}
	}

}
