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

package com.denimgroup.threadfix.scanagent.scanners;

import java.io.File;

import com.denimgroup.threadfix.cli.ThreadFixRestClient;
import org.apache.commons.configuration.Configuration;

import com.denimgroup.threadfix.data.entities.TaskConfig;
import org.apache.log4j.Logger;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public abstract class AbstractScanAgent {

    private static Logger log = Logger.getLogger(AbstractScanAgent.class);
    @NotNull
    private String workDir;
	private int currentTaskId;
    @NotNull
    private ThreadFixRestClient tfClient;
	
	public void setWorkDir(@NotNull String workDir) {
		this.workDir = workDir;
	}
	
	@NotNull
    public String getWorkDir() {
		return(this.workDir);
	}
	
	public void setCurrentTaskId(int currentTaskId) {
		this.currentTaskId = currentTaskId;
	}

    @NotNull
    public ThreadFixRestClient getTfClient() {
        return tfClient;
    }

    public void setTfClient(@NotNull ThreadFixRestClient tfClient) {
        this.tfClient = tfClient;
    }

    /**
     * Send a message back to the server for the given task. This allows
     * for server-side tracking and debugging - especially for long-running tasks.
     */
	public void sendStatusUpdate(String message) {
//		this.scanAgentRunner.sendStatusUpdate(this.currentTaskId, message);

        log.debug("Sending server update for taskId: " + this.currentTaskId + " of: " + message);
        String result = getTfClient().taskStatusUpdate(String.valueOf(this.currentTaskId), message);
        log.debug("Server response from task update was: " + result);
	}
	
	public abstract boolean readConfig(@NotNull Configuration config);
    @Nullable
    public abstract File doTask(@NotNull TaskConfig config);
}
