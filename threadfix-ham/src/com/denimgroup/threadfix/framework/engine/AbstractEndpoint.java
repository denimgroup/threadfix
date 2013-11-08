package com.denimgroup.threadfix.framework.engine;

import com.denimgroup.threadfix.framework.engine.full.Endpoint;


public abstract class AbstractEndpoint implements Endpoint {
	
	@Override
	public int compareTo(Endpoint otherEndpoint) {
		int returnValue = 0;
		
		if (otherEndpoint != null) {
			
			if (this.getFilePath() != null && otherEndpoint.getFilePath() != null) {
				returnValue -= 2 * otherEndpoint.getFilePath().compareTo(getFilePath());
			}
			
			if (getStartingLineNumber() < otherEndpoint.getStartingLineNumber()) {
				returnValue -= 1;
			} else {
				returnValue += 1;
			}
		}
		
		return returnValue;
	}
	
	// TODO finalize this
	@Override
	public String getCSVLine() {
		return getHttpMethods() + "," + getUrlPath() + "," + getParameters();
	}
	
	@Override
	public String toString() {
		return getCSVLine();
	}

}
