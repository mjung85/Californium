package ch.ethz.inf.vs.californium.coap;

public class UnsupportedRequest extends Request {

	public UnsupportedRequest(int code) {
		super(code);
	}
	
	@Override
	public boolean send() {
		LOG.severe("Cannot send UnsupportedRequest");
		return false;
	}
}
