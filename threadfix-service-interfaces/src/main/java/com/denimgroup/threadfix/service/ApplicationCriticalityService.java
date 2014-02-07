package com.denimgroup.threadfix.service;

import java.util.List;

import com.denimgroup.threadfix.data.entities.ApplicationCriticality;

/**
 * 
 * @author mcollins
 *
 */
public interface ApplicationCriticalityService {

	/**
	 * @return
	 */
	List<ApplicationCriticality> loadAll();

	/**
	 * @param applicationChannelId
	 * @return
	 */
	ApplicationCriticality loadApplicationCriticality(int applicationCriticalityId);
	
	/**
	 * @param applicationChannelName
	 * @return
	 */
	ApplicationCriticality loadApplicationCriticality(String applicationCriticalityName);
	
}
