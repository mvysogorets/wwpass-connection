package com.wwpass.connection.exceptions;

import java.net.ProtocolException;

public class WWPassProtocolException extends ProtocolException {
    /**
	 * 
	 */
	private static final long serialVersionUID = -3282962640938845591L;

	public WWPassProtocolException(String message) {
        super(message);
    }
}
