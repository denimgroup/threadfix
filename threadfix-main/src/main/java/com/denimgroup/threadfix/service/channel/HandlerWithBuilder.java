package com.denimgroup.threadfix.service.channel;

import org.xml.sax.helpers.DefaultHandler;

public abstract class HandlerWithBuilder extends DefaultHandler {
	private StringBuilder builder = new StringBuilder();

	protected void addTextToBuilder(char ch[], int start, int length) {
		builder.append(ch, start, length);
	}
	
	protected String getBuilderText() {
    	String toReturn = builder.toString();
    	builder.setLength(0);
    	return toReturn;
    }
}
