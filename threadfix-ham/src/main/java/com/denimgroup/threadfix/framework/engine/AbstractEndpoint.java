package com.denimgroup.threadfix.framework.engine;

import com.denimgroup.threadfix.framework.engine.full.Endpoint;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;


public abstract class AbstractEndpoint implements Endpoint {
	
	@Override
	public int compareTo(@Nullable Endpoint otherEndpoint) {
		int returnValue = 0;
		
		if (otherEndpoint != null) {
			
            returnValue -= 2 * otherEndpoint.getFilePath().compareTo(getFilePath());

			if (getStartingLineNumber() < otherEndpoint.getStartingLineNumber()) {
				returnValue -= 1;
			} else {
				returnValue += 1;
			}
		}
		
		return returnValue;
	}
	
	// TODO finalize this
	@NotNull
    @Override
	public String getCSVLine() {
		return getToStringNoCommas(getHttpMethods()) + "," + getUrlPath() + "," + getToStringNoCommas(getParameters());
	}
	
	private String getToStringNoCommas(@NotNull Object object) {
        return object.toString().replaceAll(",", "");
	}
	
	@NotNull
    @Override
	public String toString() {
		return getCSVLine();
	}

}
