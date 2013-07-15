package com.denimgroup.threadfix.service.merge;

import com.denimgroup.threadfix.data.entities.ApplicationChannel;
import com.denimgroup.threadfix.data.entities.Scan;

public interface ScanMerger {
	
	void merge(Scan scan, ApplicationChannel channel, ScanMergeConfiguration configuration);
	
}
