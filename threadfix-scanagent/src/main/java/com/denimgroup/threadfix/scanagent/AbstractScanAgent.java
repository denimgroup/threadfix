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

package com.denimgroup.threadfix.scanagent;

import java.io.File;

import org.apache.commons.configuration.Configuration;

import com.denimgroup.threadfix.data.entities.TaskConfig;
import org.jetbrains.annotations.NotNull;

public abstract class AbstractScanAgent {
	@NotNull
    private String workDir;
    @NotNull
    private ServerConduit serverConduit;
	//	TODO - The was we handle this is pretty gross. And brittle. Reorganize.
	private int currentTaskId;
	
	public void setWorkDir(@NotNull String workDir) {
		this.workDir = workDir;
	}
	
	public String getWorkDir() {
		return(this.workDir);
	}
	
	public void setServerConduit(@NotNull ServerConduit serverConduit) {
		this.serverConduit = serverConduit;
	}
	
	public void setCurrentTaskId(int currentTaskId) {
		this.currentTaskId = currentTaskId;
	}
	
	
	
	/**
	 * Allow the 
	 * @param message
	 */
	public void sendStatusUpdate(String message) {
		this.serverConduit.sendStatusUpdate(this.currentTaskId, message);
	}
	
	public abstract boolean readConfig(@NotNull Configuration config);
    public abstract File doTask(@NotNull TaskConfig config);
}
