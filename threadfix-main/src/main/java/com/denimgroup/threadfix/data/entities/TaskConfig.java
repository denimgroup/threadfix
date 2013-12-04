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

package com.denimgroup.threadfix.data.entities;

import org.jetbrains.annotations.NotNull;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 * TODO - Need to Hibernate this up
 * @author dcornell
 *
 */
public class TaskConfig {
    @NotNull
	private URL targetUrl;
	private Map<String,byte[]> dataBlobs;
	private Map<String,String> configParams;
	
	public TaskConfig() {
		this.dataBlobs = new HashMap<>();
		this.configParams = new HashMap<>();
	}
	
	public TaskConfig(@NotNull URL targetUrl) {
		this.targetUrl = targetUrl;
		this.dataBlobs = new HashMap<>();
		this.configParams = new HashMap<>();
	}
	
	public void setDataBlob(String key, byte[] value) {
		this.dataBlobs.put(key,  value);
	}
	
	public byte[] getDataBlob(String key) {
		return this.dataBlobs.get(key);
	}
	
	public Map<String, byte[]> getDataBlobs() {
		//	TODO - Determine if we need to clone this - might get kinda big
		return this.dataBlobs;
	}
	
	public void setConfigParam(String key, String value) {
		this.configParams.put(key, value);
	}

	public String getConfigParam(String key) {
		return this.configParams.get(key);
	}
	
	public Map<String, String> getConfigParams() {
		//	TODO - Determine if we need to clone this - might get kinda big
		return this.configParams;
	}
	
	public void setTargetUrlString(@NotNull String targetUrlString) {
			try {
				this.targetUrl = new URL(targetUrlString);
			} catch (MalformedURLException e) {
				// TODO - Figure out what to do if we get a bad URL
				e.printStackTrace();
			}
	}

    @NotNull
	public URL getTargetUrl() {
		return this.targetUrl;
	}

    @NotNull
	public String getTargetUrlString() {
		return this.targetUrl.toString();
	}
	
	@Override
	public String toString() {
		String retVal = "TaskConfig { targetUrl=" + this.targetUrl + " }";
		
		return retVal;
	}
}
