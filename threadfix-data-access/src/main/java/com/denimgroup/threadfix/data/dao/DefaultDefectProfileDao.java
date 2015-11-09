package com.denimgroup.threadfix.data.dao;

import com.denimgroup.threadfix.data.entities.DefaultDefectProfile;

public interface DefaultDefectProfileDao extends GenericObjectDao<DefaultDefectProfile> {

	public void deleteById(int defaultDefectProfileId);
	public DefaultDefectProfile retrieveDefectProfileByName(String name, Integer defectTrackerId, Integer appId);

}
