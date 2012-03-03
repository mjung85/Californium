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
 * This file is part of the Californium CoAP framework.
 ******************************************************************************/
package ch.ethz.inf.vs.californium.coap;

import java.io.IOException;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * The Class Request describes the functionality of a CoAP Request as a subclass
 * of a CoAP {@link Message}. It provides operations to answer a request by a {@link Response}
 * using {@link #respond(Response)}. There are different ways to handle incoming
 * responses:
 * <ol>
 * <li>by overriding the protected method {@link #handleResponse(Response)}, e.g.,
 * using anonymous inner classes
 * <li>by registering a handler using {@link #registerResponseHandler(ResponseHandler)}
 * <li>by calling the blocking method {@link #receiveResponse()}
 * </ol>
 * 
 * @author Dominique Im Obersteg, Daniel Pauli, and Matthias Kovatsch
 */
public class Request extends Message {
	
	// Constants ///////////////////////////////////////////////////////////////
	
	/** The time when a request was issued. */
	private static final long startTime = System.currentTimeMillis();

	// Constructors ////////////////////////////////////////////////////////////

	/**
	 * Instantiates a new request.
	 *
	 * @param code The method code of the message
	 * @param confirmable True if the request is to be sent as a confirmable
	 */
	public Request(int code, boolean confirmable) {
		super(confirmable ? messageType.Confirmable
				: messageType.Non_Confirmable, code);
	}

	// Methods /////////////////////////////////////////////////////////////////

	/**
	 * Executes the request on the endpoint specified by the message's URI
	 *
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public void execute() throws IOException {

		Communicator comm = communicator != null ? communicator : defaultCommunicator();
		if (comm != null) {
			comm.sendMessage(this);
		}
	}

	/*
	 * 
	 * 
	 * @param response A response to this request
	 */
	/**
	 * Places a new response to this request
	 *
	 * @param response The response buddy for this request
	 */
	public void respond(Response response) {

		// assign response to this request
		response.setRequest(this);

		response.setPeerAddress( getPeerAddress() );

		// Reflect token
		response.setOption(this.getFirstOption( OptionNumberRegistry.TOKEN) );
		response.requiresToken = requiresToken;

		if (responseCount == 0 && isConfirmable()) {
			response.setMID(getMID());
		}
		
		// echo block1 option
		BlockOption block1 = (BlockOption) this.getFirstOption( OptionNumberRegistry.BLOCK1 );
		if (block1!=null) {
			response.addOption(block1);
		}

		// set message type
		if (response.getType() == null) {
			if (responseCount == 0 && isConfirmable()) {
				// use piggy-backed response
				response.setType(messageType.Acknowledgement);
			} else {
				// use separate response:
				// Confirmable response to confirmable request,
				// Non-confirmable response to non-confirmable request
				response.setType(getType());
			}
		}

		// check observe option
		Option observeOpt = getFirstOption(OptionNumberRegistry.OBSERVE);
		if (observeOpt != null
				&& !response.hasOption(OptionNumberRegistry.OBSERVE)) {

			// 16-bit second counter
			int secs = (int) ((System.currentTimeMillis() - startTime) / 1000) & 0xFFFF;

			response.setOption(new Option(secs, OptionNumberRegistry.OBSERVE));

			if (response.isConfirmable()) {
				response.setType(messageType.Non_Confirmable);
			}
		}

		// check if response is of remote origin, i.e.
		// was received by a communicator
		if (communicator != null)
			try {
				communicator.sendMessage(response);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();

			}
		else {

			// handle locally
			response.handle();
		}

		++responseCount;
	}

	/**
	 * Respond.
	 *
	 * @param code the code
	 * @param message the message
	 */
	public void respond(int code, String message) {
		Response response = new Response(code);
		if (message != null) {
			response.setPayload(message);
		}
		respond(response);
	}

	/**
	 * Respond.
	 *
	 * @param code the code
	 */
	public void respond(int code) {
		respond(code, null);
	}

	/**
	 * Accept.
	 */
	public void accept() {
		if (isConfirmable()) {
			Response ack = new Response(CodeRegistry.EMPTY_MESSAGE);
			ack.setType(messageType.Acknowledgement);
			respond(ack);
		}
	}

	/**
	 * Reject.
	 */
	public void reject() {
		if (isConfirmable()) {
			Response rst = new Response(CodeRegistry.EMPTY_MESSAGE);
			rst.setType(messageType.Reset);
			respond(rst);
		}
	}

	/**
	 * Sets the communicator.
	 *
	 * @param communicator the new communicator
	 */
	public void setCommunicator(Communicator communicator) {
		this.communicator = communicator;
	}

	/*
	 * Returns a response that was placed using respond() and blocks until such
	 * a response is available.
	 * 
	 * NOTE: In order to safely use this method, the call useResponseQueue(true)
	 * is required BEFORE any possible respond() calls take place
	 * 
	 * @return The next response that was placed using respond()
	 */
	/**
	 * Receive response.
	 *
	 * @return the response
	 * @throws InterruptedException the interrupted exception
	 */
	public Response receiveResponse() throws InterruptedException {

		// response queue required to perform this operation
		if (!responseQueueEnabled()) {
			System.out
					.println("WARNING: Missing useResponseQueue(true) call, responses may be lost");
			enableResponseQueue(true);
		}

		// take response from queue
		Response response = responseQueue.take();

		// return null if request timed out
		return response != TIMEOUT_RESPONSE ? response : null;
	}

	/* (non-Javadoc)
	 * @see ch.ethz.inf.vs.californium.coap.Message#handleTimeout()
	 */
	@Override
	public void handleTimeout() {
		if (responseQueueEnabled()) {
			responseQueue.offer(TIMEOUT_RESPONSE);
		}
	}

	/*
	 * Registers a handler for responses to this request
	 * 
	 * @param handler The observer to add to the handler list
	 */
	/**
	 * Register response handler.
	 *
	 * @param handler the handler
	 */
	public void registerResponseHandler(ResponseHandler handler) {

		if (handler != null) {

			// lazy creation of response handler list
			if (responseHandlers == null) {
				responseHandlers = new ArrayList<ResponseHandler>();
			}

			responseHandlers.add(handler);
		}
	}

	/*
	 * Unregisters a handler for responses to this request
	 * 
	 * @param handler The observer to remove from the handler list
	 */
	/**
	 * Unregister response handler.
	 *
	 * @param handler the handler
	 */
	public void unregisterResponseHandler(ResponseHandler handler) {

		if (handler != null && responseHandlers != null) {

			responseHandlers.remove(handler);
		}
	}

	/*
	 * Enables or disables the response queue
	 * 
	 * NOTE: The response queue needs to be enabled BEFORE any possible calls to
	 * receiveResponse()
	 * 
	 * @param enable True to enable and false to disable the response queue,
	 * respectively
	 */
	/**
	 * Enable response queue.
	 *
	 * @param enable the enable
	 */
	public void enableResponseQueue(boolean enable) {
		if (enable != responseQueueEnabled()) {
			responseQueue = enable ? new LinkedBlockingQueue<Response>() : null;
		}
	}

	/*
	 * Checks if the response queue is enabled
	 * 
	 * NOTE: The response queue needs to be enabled BEFORE any possible calls to
	 * receiveResponse()
	 * 
	 * @return True iff the response queue is enabled
	 */
	/**
	 * Response queue enabled.
	 *
	 * @return true, if successful
	 */
	public boolean responseQueueEnabled() {
		return responseQueue != null;
	}

	// Subclassing /////////////////////////////////////////////////////////////

	/*
	 * This method is called whenever a response was placed to this request.
	 * Subclasses can override this method in order to handle responses.
	 * 
	 * @param response The response to handle
	 */
	/**
	 * Handle response.
	 *
	 * @param response the response
	 */
	protected void handleResponse(Response response) {

		// enqueue response
		if (responseQueueEnabled()) {
			if (!responseQueue.offer(response)) {
				System.out
						.println("ERROR: Failed to enqueue response to request");
			}
		}

		// notify response handlers
		if (responseHandlers != null) {
			for (ResponseHandler handler : responseHandlers) {
				handler.handleResponse(response);
			}
		}

	}

	/**
	 * Response payload appended.
	 *
	 * @param response the response
	 * @param block the block
	 */
	protected void responsePayloadAppended(Response response, byte[] block) {
		// do nothing
	}

	/**
	 * Response completed.
	 *
	 * @param response the response
	 */
	protected void responseCompleted(Response response) {
		// do nothing
	}

	/*
	 * Direct subclasses need to override this method in order to invoke the
	 * according method of the provided RequestHandler (visitor pattern)
	 * 
	 * @param handler A handler for this request
	 */
	/**
	 * Dispatch.
	 *
	 * @param handler the handler
	 */
	public void dispatch(RequestHandler handler) {
		System.out.printf("Unable to dispatch request with code '%s'",
				CodeRegistry.toString(getCode()));
	}

	/* (non-Javadoc)
	 * @see ch.ethz.inf.vs.californium.coap.Message#handleBy(ch.ethz.inf.vs.californium.coap.MessageHandler)
	 */
	@Override
	public void handleBy(MessageHandler handler) {
		handler.handleRequest(this);
	}

	// Class functions /////////////////////////////////////////////////////////

	/*
	 * Returns the default communicator used for outgoing requests
	 * 
	 * @return The default communicator
	 */
	/**
	 * Default communicator.
	 *
	 * @return the communicator
	 */
	public static Communicator defaultCommunicator() {

		// lazy initialization
		if (DEFAULT_COMM == null) {
			try {
				DEFAULT_COMM = new Communicator();
			} catch (SocketException e) {
				System.out.printf(
						"[%s] Failed to create default communicator: %s\n",
						"JCoAP", e.getMessage());
			}
		}
		return DEFAULT_COMM;
	}

	// Class attributes ////////////////////////////////////////////////////////

	// the default communicator for request objects (lazy initialized)
	/** The DEFAUL t_ comm. */
	private static Communicator DEFAULT_COMM;

	/** The Constant TIMEOUT_RESPONSE. */
	private static final Response TIMEOUT_RESPONSE = new Response();

	// Attributes //////////////////////////////////////////////////////////////

	/** The communicator. */
	private Communicator communicator;

	// list of response handlers that are notified about incoming responses
	/** The response handlers. */
	private List<ResponseHandler> responseHandlers;

	// queue used to store responses that will be retrieved using
	// receiveResponse()
	/** The response queue. */
	private BlockingQueue<Response> responseQueue;

	// number of responses to this request
	/** The response count. */
	private int responseCount;
}
