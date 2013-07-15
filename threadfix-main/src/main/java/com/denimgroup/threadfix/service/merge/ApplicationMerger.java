package com.denimgroup.threadfix.service.merge;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Scan;

public interface ApplicationMerger {
	void applicationMerge(Scan scan, int applicationId, Integer statusId);
	void applicationMerge(Scan scan, Application application, Integer statusId);
}
