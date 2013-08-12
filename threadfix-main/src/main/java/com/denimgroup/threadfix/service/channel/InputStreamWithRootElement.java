package com.denimgroup.threadfix.service.channel;

import java.io.IOException;
import java.io.InputStream;

/**
 * Decorator pattern around input stream to add enclosing tag.
 * This class does not support mark or reset even if the underlying stream does.
 * @author mcollins
 *
 */
public class InputStreamWithRootElement extends InputStream {
	private InputStream stream = null;
	private StringBuilder tag;
	private final String tagToAdd;
	State currentState = State.START;
	
	private enum State {
		START, FIRST_TAG, MIDDLE, LAST_TAG, DONE
	}
	
	public InputStreamWithRootElement(InputStream stream, String rootElement) {
		this.stream = stream;
		this.tagToAdd = rootElement;
	}
	
	@Override
	public int read() throws IOException {
		switch (currentState) {
			case START     : return readFromStream();
			case FIRST_TAG : return readFromTag();
			case MIDDLE    : return readFromStream();
			case LAST_TAG  : return readFromTag();
			case DONE      : return -1;
			default        : return -1;
		}
	}
	
	private int readFromTag() {
		int charToReturn = tag.charAt(0);
		
		if (tag.length() <= 1) {
			tag = null;
			if (currentState == State.FIRST_TAG) {
				currentState = State.MIDDLE;
			} else {
				currentState = State.DONE;
			}
		} else {
			tag = tag.deleteCharAt(0);
		}
		
		return charToReturn;
	}
	
	private int readFromStream() throws IOException {
		int charToReturn = stream.read();
		
		if (currentState == State.MIDDLE && charToReturn == -1) {
			tag = new StringBuilder("/" + tagToAdd + ">");
			charToReturn = (int) '<';
			currentState = State.LAST_TAG;
		}
		
		if (currentState == State.START && charToReturn == (char) '>') {
			currentState = State.FIRST_TAG;
			tag = new StringBuilder("<" + tagToAdd + ">");
		}
		return charToReturn;
	}
	
	@Override
	public void close() throws IOException {
		stream.close();
	}
	
	@Override
	public boolean markSupported() {
		return false;
	}
}
