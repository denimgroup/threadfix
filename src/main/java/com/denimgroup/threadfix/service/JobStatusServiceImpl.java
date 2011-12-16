////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.service;

import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.JobStatusDao;
import com.denimgroup.threadfix.data.entities.JobStatus;

@Service
@Transactional(readOnly = true)
public class JobStatusServiceImpl implements JobStatusService {

	private JobStatusDao jobStatusDao = null;

	@Autowired
	public JobStatusServiceImpl(JobStatusDao jobStatusDao) {
		this.jobStatusDao = jobStatusDao;
	}

	@Override
	public List<JobStatus> loadAll() {
		return jobStatusDao.retrieveAll();
	}

	@Override
	public List<JobStatus> loadAllOpen() {
		return jobStatusDao.retrieveAllOpen();
	}

	@Override
	public JobStatus loadJobStatus(int id) {
		return jobStatusDao.retrieveById(id);
	}

	@Override
	public void storeJobStatus(JobStatus jobStatus) {
		jobStatusDao.saveOrUpdate(jobStatus);

	}

	@Override
	@Transactional(readOnly = false)
	public void closeJobStatus(JobStatus jobStatus, String status) {
		if (jobStatus == null) {
			return;
		}

		Date now = new Date();
		jobStatus.setStatus(status);
		jobStatus.setEndDate(now);
		jobStatus.setModifiedDate(now);
		jobStatus.setOpen(false);

		storeJobStatus(jobStatus);
	}

	@Override
	@Transactional(readOnly = false)
	public void updateJobStatus(JobStatus jobStatus, String status) {
		if (jobStatus == null) {
			return;
		}

		jobStatus.setStatus(status);
		jobStatus.setModifiedDate(new Date());

		storeJobStatus(jobStatus);
	}

	@Override
	@Transactional(readOnly = false)
	public Integer createNewJobStatus(String type, String initialStatus, String urlPath,
			String urlText) {
		JobStatus jobStatus = new JobStatus();

		Date now = new Date();

		jobStatus.setType(type);
		jobStatus.setStatus(initialStatus);
		jobStatus.setStartDate(now);
		jobStatus.setModifiedDate(now);
		jobStatus.setUrlPath(urlPath);
		jobStatus.setUrlText(urlText);
		jobStatus.setOpen(true);

		storeJobStatus(jobStatus);

		return jobStatus.getId();

	}

}
