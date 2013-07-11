package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.Finding;

public interface ManualFindingService {
	

	/**
	 * 
	 * @param finding
	 * @param applicationId
	 * @return
	 */
	boolean processManualFindingEdit(Finding finding, Integer applicationId);
	
	/**
	 * Given new Finding information, create a Scan or link to the manual scan
	 * and put the new Finding on it.
	 * 
	 * @param finding
	 * @param applicationId
	 * @param userName
	 * @return
	 */
	boolean processManualFinding(Finding finding, Integer applicationId);

}
