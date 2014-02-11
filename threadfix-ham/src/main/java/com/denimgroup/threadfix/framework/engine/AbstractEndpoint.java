////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////

package com.denimgroup.threadfix.framework.engine;

import com.denimgroup.threadfix.data.interfaces.Endpoint;
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
