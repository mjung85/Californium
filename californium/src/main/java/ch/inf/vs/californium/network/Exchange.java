package ch.inf.vs.californium.network;

import java.util.concurrent.ScheduledFuture;

import ch.inf.vs.californium.coap.BlockOption;
import ch.inf.vs.californium.coap.CoAP.Type;
import ch.inf.vs.californium.coap.EmptyMessage;
import ch.inf.vs.californium.coap.Request;
import ch.inf.vs.californium.coap.Response;

public class Exchange {

	// TODO: When implementing observer we need to be able to make threads stop
	// modifying the exchange. A thread working on blockwise transfer might
	// access fields that are about to change with each new response. The same
	// mech. can be used to cancel an exchange. Use an AtomicInteger to count
	// threads that are currently working on the exchange.
	
	private Endpoint endpoint;
	
	private Request request; // the initial request we have to exchange
	private Request currentRequest; // Matching needs to know for what we expect a response
	private BlockwiseStatus requestBlockStatus;
	
	private Response response;
	private Response currentResponse; // Matching needs to know when receiving duplicate
	private BlockwiseStatus responseBlockStatus;
	
	// true if the local server has initiated this exchange
	private final boolean fromLocal;
	
	// true if the exchange has failed due to a timeout
	private boolean timeouted;
	
	// the timeout of the current request or response set by reliability layer
	private int currentTimeout;
	
	// the amount of attempted transmissions that have not succeeded yet
	private int transmissionCount = 0;

	// handle to cancel retransmission
	private ScheduledFuture<?> retransmissionHandle;
	
	// If the request was sent with a block1 option the response has to send its
	// first block piggy-backed with the Block1 option of the last request block
	private BlockOption block1ToAck;
	
	public Exchange(Request request, boolean fromLocal) {
		this.currentRequest = request; // might only be the first block of the whole request
		this.fromLocal = fromLocal;
	}
	
	public void accept() {
		assert(!fromLocal);
		if (request.getType() == Type.CON && !request.isAcknowledged()) {
			request.setAcknowledged(true);
			EmptyMessage ack = EmptyMessage.newACK(request);
			endpoint.sendEmptyMessage(this, ack);
		}
	}
	
	public void reject() {
		assert(!fromLocal);
		request.setRejected(true);
		EmptyMessage rst = EmptyMessage.newRST(request);
		endpoint.sendEmptyMessage(this, rst);
	}
	
	public void respond(Response response) {
		assert(endpoint != null);
		// TODO: Should this routing stuff be done within a layer?
		response.setMid(request.getMid()); // TODO: Careful with MIDs
		response.setDestination(request.getSource());
		response.setDestinationPort(request.getSourcePort());
		this.currentResponse = response;
		endpoint.sendResponse(this, response);
	}

	public boolean isFromLocal() {
		return fromLocal;
	}
	
	public Request getRequest() {
		return request;
	}
	
	public void setRequest(Request request) {
		this.request = request; // by blockwise layer
	}

	public Request getCurrentRequest() {
		return currentRequest;
	}

	public void setCurrentRequest(Request currentRequest) {
		this.currentRequest = currentRequest;
	}

	public BlockwiseStatus getRequestBlockStatus() {
		return requestBlockStatus;
	}

	public void setRequestBlockStatus(BlockwiseStatus requestBlockStatus) {
		this.requestBlockStatus = requestBlockStatus;
	}

	public Response getResponse() {
		return response;
	}

	public void setResponse(Response response) {
		this.response = response;
	}

	public Response getCurrentResponse() {
		return currentResponse;
	}

	public void setCurrentResponse(Response currentResponse) {
		this.currentResponse = currentResponse;
	}

	public BlockwiseStatus getResponseBlockStatus() {
		return responseBlockStatus;
	}

	public void setResponseBlockStatus(BlockwiseStatus responseBlockStatus) {
		this.responseBlockStatus = responseBlockStatus;
	}

	public BlockOption getBlock1ToAck() {
		return block1ToAck;
	}

	public void setBlock1ToAck(BlockOption block1ToAck) {
		this.block1ToAck = block1ToAck;
	}
	
	public Endpoint getEndpoint() {
		return endpoint;
	}

	public void setEndpoint(Endpoint endpoint) {
		this.endpoint = endpoint;
	}

	public boolean isTimeouted() {
		return timeouted;
	}

	public void setTimeouted(boolean timeouted) {
		this.timeouted = timeouted;
	}

	public int getTransmissionCount() {
		return transmissionCount;
	}

	public void setTransmissionCount(int transmissionCount) {
		this.transmissionCount = transmissionCount;
	}

	public int getCurrentTimeout() {
		return currentTimeout;
	}

	public void setCurrentTimeout(int currentTimeout) {
		this.currentTimeout = currentTimeout;
	}

	public ScheduledFuture<?> getRetransmissionHandle() {
		return retransmissionHandle;
	}

	public void setRetransmissionHandle(ScheduledFuture<?> retransmissionHandle) {
		this.retransmissionHandle = retransmissionHandle;
	}
}