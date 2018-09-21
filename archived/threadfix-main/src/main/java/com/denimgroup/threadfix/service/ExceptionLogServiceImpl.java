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

import com.denimgroup.threadfix.data.dao.ExceptionLogDao;
import com.denimgroup.threadfix.data.entities.ExceptionLog;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static com.denimgroup.threadfix.util.TFManifestProperties.MANIFEST_GIT_COMMIT;

@Service
@Transactional(readOnly = false)
public class ExceptionLogServiceImpl implements ExceptionLogService {

	@Autowired
	private ExceptionLogDao exceptionLogDao;
	
	@Override
	public void storeExceptionLog(ExceptionLog exceptionLog) {
		exceptionLog.setCommit(MANIFEST_GIT_COMMIT);
		exceptionLogDao.saveOrUpdate(exceptionLog);
	}

	@Override
	public List<ExceptionLog> loadAll() {
		return exceptionLogDao.retrieveAll();
	}

    @Override
    public List<ExceptionLog> loadPage(int page, int numberToShow) {
        return exceptionLogDao.retrievePage(page, numberToShow);
    }

    @Override
    public Long countLogs() {
        return exceptionLogDao.countLogs();
    }

}
