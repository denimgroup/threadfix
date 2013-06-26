////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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

package com.denimgroup.threadfix.scanagent.configuration;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class TaskConfig {
	private URL targetUrl;
	private Map<String,byte[]> dataBlobs;
	private Map<String,String> configParams;
	
	public TaskConfig(URL targetUrl) {
		this.targetUrl = targetUrl;
		this.dataBlobs = new HashMap<String,byte[]>();
		this.configParams = new HashMap<String,String>();
	}
	
	public void setDataBlog(String key, byte[] value) {
		this.dataBlobs.put(key,  value);
	}
	
	public byte[] getDataBlob(String key) {
		return(this.dataBlobs.get(key));
	}
	
	public void setConfigParam(String key, String value) {
		this.configParams.put(key, value);
	}

	public String getConfigParam(String key) {
		return(this.configParams.get(key));
	}
	
	public URL getTargetUrl() {
		return(this.targetUrl);
	}
	
	public String getTargetUrlString() {
		return(this.targetUrl.toString());
	}
	
	public String toString() {
		String retVal = "TaskConfig { targetUrl=" + this.targetUrl + " }";
		
		return(retVal);
	}
}
