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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.FindingDao;
import com.denimgroup.threadfix.data.entities.ChannelSeverity;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.ChannelVulnerability;
import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;
import com.denimgroup.threadfix.webapp.controller.AddFindingRestController;

@Service
@Transactional(readOnly = true)
public class FindingServiceImpl implements FindingService {

	private FindingDao findingDao = null;
	private ChannelVulnerabilityDao channelVulnerabilityDao = null;
	private ChannelTypeDao channelTypeDao = null;

	protected final Log log = LogFactory.getLog(FindingServiceImpl.class);
	
	@Autowired
	public FindingServiceImpl(FindingDao findingDao,
			ChannelVulnerabilityDao channelVulnerabilityDao,
			ChannelTypeDao channelTypeDao) {
		this.findingDao = findingDao;
		this.channelTypeDao = channelTypeDao;
		this.channelVulnerabilityDao = channelVulnerabilityDao;
	}

	@Override
	public List<Finding> loadAll() {
		return findingDao.retrieveAll();
	}

	@Override
	public Finding loadFinding(int findingId) {
		return findingDao.retrieveById(findingId);
	}
	
	@Override
	public List<String> loadSuggested(String hint, int appId) {
		return findingDao.retrieveByHint(hint, appId);
	}
	
	@Override
	public List<Finding> loadLatestStaticByAppAndUser(int appId, int userId) {
		return findingDao.retrieveLatestStaticByAppAndUser(appId, userId);
	}
	
	@Override
	public List<Finding> loadLatestDynamicByAppAndUser(int appId, int userId) {
		return findingDao.retrieveLatestDynamicByAppAndUser(appId, userId);
	}

	@Override
	@Transactional(readOnly = false)
	public void storeFinding(Finding finding) {
		findingDao.saveOrUpdate(finding);
	}
	
	@Override
	public Finding parseFindingFromRequest(HttpServletRequest request) {
		String staticParameter = request.getParameter("isStatic");
		boolean isStatic = staticParameter != null && staticParameter.equals("true");
		
		Finding finding = new Finding();
		SurfaceLocation location = new SurfaceLocation();
		ChannelSeverity channelSeverity = new ChannelSeverity();
		ChannelVulnerability channelVulnerability = new ChannelVulnerability();
				
		finding.setSurfaceLocation(location);
				
		String vulnType = request.getParameter("vulnType");
		channelVulnerability.setCode(vulnType);
		finding.setChannelVulnerability(channelVulnerability);
		
		String longDescription = request.getParameter("longDescription");
		if (longDescription != null && !longDescription.trim().equals("") && 
				longDescription.length() < Finding.LONG_DESCRIPTION_LENGTH) {
			finding.setLongDescription(longDescription);
		}
		
		String severity = request.getParameter("severity");
		channelSeverity.setId(getInt(severity));
		finding.setChannelSeverity(channelSeverity);
		
		String nativeId = request.getParameter("nativeId");
		if (nativeId != null && nativeId.length() < Finding.NATIVE_ID_LENGTH) {
			finding.setNativeId(nativeId);
		}
		
		String parameter = request.getParameter("parameter");
		if (parameter != null && parameter.length() < SurfaceLocation.PARAMETER_LENGTH) {
			location.setParameter(parameter);
		}
		
		if (isStatic) {
			log.info("The 'static' parameter was set to 'true', a static finding is being created.");
			String filePath = request.getParameter("filePath");
			String column = request.getParameter("column");
			String lineText = request.getParameter("lineText");
			String lineNumber = request.getParameter("lineNumber");
			
			finding.setIsStatic(true);
			
			DataFlowElement element = new DataFlowElement(filePath, getInt(lineNumber), lineText, 0);
			element.setColumnNumber(getInt(column));
			finding.setDataFlowElements(new ArrayList<DataFlowElement>());
			finding.getDataFlowElements().add(element);
		} else {
			log.info("The 'static' parameter was not present or not 'true'," +
					" a dynamic finding is being created.");
			
			String fullUrl = request.getParameter("fullUrl");
			location.setUrl(getUrl(fullUrl));
			String path = request.getParameter("path");
			if (path != null) {
				location.setPath(path);
			}
		}
		
		return finding;
	}
	
	/**
	 * 
	 */
	public String checkRequestForFindingParameters(HttpServletRequest request) {
		if (request == null) {
			return null;
		}
		
		String longDescription = request.getParameter("longDescription");
		if (longDescription == null || longDescription.trim().equals("") || 
				longDescription.length() > Finding.LONG_DESCRIPTION_LENGTH) {
			return AddFindingRestController.INVALID_DESCRIPTION;
		}
		
		String vulnType = request.getParameter("vulnType");
		ChannelVulnerability channelVulnerability = null;
		if (vulnType != null) {
			channelVulnerability = channelVulnerabilityDao
				.retrieveByCode(
						channelTypeDao.retrieveByName(ChannelType.MANUAL),
						vulnType);
		}
		
		if (vulnType == null || channelVulnerability == null) {
			return AddFindingRestController.INVALID_VULN_NAME;
		}
		
		return AddFindingRestController.PASSED_CHECK;
	}
	
	/**
	 * This method just wraps the try / catch MalformedURLException of Integer.valueOf
	 * to ease String parsing.
	 * @param intString
	 * @return
	 */
	private int getInt(String intString) {
		try {
			return Integer.valueOf(intString);
		} catch (NumberFormatException e) {
			log.warn("Tried to parse an integer out of a user-supplied String but failed.");
		}
		
		return -1;
	}
	
	/**
	 * This method just wraps the try / catch MalformedURLException of URL()
	 * to ease String parsing.
	 * @param possibleURL
	 * @return
	 */
	private URL getUrl(String possibleURL) {
		try {
			return new URL(possibleURL);
		} catch (MalformedURLException e) {
			log.warn("Tried to parse a URL out of a user-supplied String but failed.");
		}
		
		return null;
	}
	
	

}
