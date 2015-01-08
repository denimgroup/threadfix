////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
package com.denimgroup.threadfix.service;

import java.util.Calendar;
import java.util.List;

import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.JobStatus;

/**
 * @author bbeverly
 * 
 */
public interface JobStatusService {

	/**
	 * @return
	 */
	List<JobStatus> loadAll();

	/**
	 * @return
	 */
	List<JobStatus> loadAllOpen();

	/**
	 * @param id
	 * @return
	 */
	JobStatus loadJobStatus(int id);

	/**
	 * @param jobStatus
	 */
	void storeJobStatus(JobStatus jobStatus);

	/**
	 * Set a JobStatus's status to closed so that it moves off the queue.
	 * 
	 * @param jobStatus
	 * @param status
	 */
	void closeJobStatus(JobStatus jobStatus, String status);

	/**
	 * Open the JobStatus and change its message and save it so that 
	 * people watching the queue can see progress.
	 * 
	 * @param jobStatus
	 * @param status
	 */
	void updateJobStatus(Integer jobStatusId, String status);

	/**
	 * Create a new JobStatus object and return its ID so that it can be retrieved easily later.
	 * 
	 * @param type
	 * @param initialStatus
	 * @param urlPath
	 * @param urlText
	 * @return
	 */
	Integer createNewJobStatus(String type, String initialStatus, String urlPath, String urlText,
								Calendar date, ApplicationChannel channel);

}
