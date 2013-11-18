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
package com.denimgroup.threadfix.service;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.PathVariable;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.FindingDao;
import com.denimgroup.threadfix.data.dao.GenericVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.UserDao;
import com.denimgroup.threadfix.data.entities.ChannelSeverity;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.ChannelVulnerability;
import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.data.entities.SurfaceLocation;
import com.denimgroup.threadfix.data.entities.User;
import com.denimgroup.threadfix.webapp.controller.AddFindingRestController;
import com.denimgroup.threadfix.webapp.controller.TableSortBean;

@Service
@Transactional(readOnly = true)
public class FindingServiceImpl implements FindingService {

	private FindingDao findingDao = null;
	private ChannelVulnerabilityDao channelVulnerabilityDao = null;
	private GenericVulnerabilityDao genericVulnerabilityDao = null;
	private UserDao userDao = null;
	private ChannelTypeDao channelTypeDao = null;
	private ChannelSeverityDao channelSeverityDao = null;

	private final SanitizedLogger log = new SanitizedLogger(FindingServiceImpl.class);
	
	@Autowired
	public FindingServiceImpl(FindingDao findingDao,
			ChannelSeverityDao channelSeverityDao,
			ChannelVulnerabilityDao channelVulnerabilityDao,
			GenericVulnerabilityDao genericVulnerabilityDao,
			ChannelTypeDao channelTypeDao, UserDao userDao) {
		this.findingDao = findingDao;
		this.channelTypeDao = channelTypeDao;
		this.channelSeverityDao = channelSeverityDao;
		this.userDao = userDao;
		this.genericVulnerabilityDao = genericVulnerabilityDao;
		this.channelVulnerabilityDao = channelVulnerabilityDao;
	}
	
	@Override
	public void validateManualFinding(Finding finding, BindingResult result) {
		
		
		if (finding == null || ((finding.getChannelVulnerability() == null) || 
				(finding.getChannelVulnerability().getCode() == null) ||
				(finding.getChannelVulnerability().getCode().isEmpty()))) {
			result.rejectValue("channelVulnerability.code", "errors.required", new String [] { "Vulnerability" }, null);
		} else {
			String code = finding.getChannelVulnerability().getCode();
			finding.getChannelVulnerability().setCode(code.substring(0, code.indexOf("(CWE")).trim());
			
			if (!channelVulnerabilityDao.isValidManualName(finding.getChannelVulnerability().getCode())) {

				boolean wasNumeric = false;

				// Try to parse an ID from the string and use that
				ChannelVulnerability newChannelVuln = null;
				try {
					Integer requestedId = Integer.valueOf(finding.getChannelVulnerability().getCode());

					if (requestedId != null) {
						wasNumeric = true;
						String cweName = null;
						ChannelType manualType = null;
						GenericVulnerability genericVulnerability = genericVulnerabilityDao.retrieveById(requestedId);
						if (genericVulnerability != null) {
							cweName = genericVulnerability.getName();
							if (cweName != null) {
								manualType = channelTypeDao.retrieveByName(ScannerType.MANUAL.getFullName());
								if (manualType != null) {
									newChannelVuln = channelVulnerabilityDao.retrieveByName(manualType, cweName);
								}
							}
						}

						if (newChannelVuln != null) {
							// id lookup success, set the name to the actual name instead of the id.
							finding.getChannelVulnerability().setCode(newChannelVuln.getCode());
						}
					}

				} catch (NumberFormatException e) {
					log.info("The code passed in was not a valid manual name and was not a number.");
				}

				if (newChannelVuln == null) {
					// ID lookup failed
					if (wasNumeric) {
						result.rejectValue("channelVulnerability.code", null, null, "The supplied ID was invalid." +
								" Please enter a valid CWE name or ID from http://cwe.mitre.org/");
					} else {
						result.rejectValue("channelVulnerability.code", null, null, "The supplied name was invalid. " +
								"Please enter a valid CWE name or ID (example: 79) from http://cwe.mitre.org/");
					}
				}
			}
		}

		if (finding != null && (finding.getLongDescription() == null || 
				finding.getLongDescription().trim().isEmpty())) {
			result.rejectValue("longDescription", "errors.required", new String [] { "Description" }, null);
		}

		FieldError originalError = result.getFieldError("dataFlowElements[0].lineNumber");
		if (originalError != null && originalError.getDefaultMessage()
				.startsWith("Failed to convert property value of type " +
						"'java.lang.String' to required type 'int'")) {
			result.rejectValue("dataFlowElements[0]", "errors.invalid", new String [] { "Line number" }, null);
		}
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
						channelTypeDao.retrieveByName(ScannerType.MANUAL.getFullName()),
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
	
	
	@Override
	public List<Finding> getFindingTable(Integer scanId, TableSortBean bean) {
		return findingDao.retrieveFindingsByScanIdAndPage(scanId, bean.getPage());
	}

	@Override
	public Object getUnmappedFindingTable(Integer scanId, TableSortBean bean) {
		return findingDao.retrieveUnmappedFindingsByScanIdAndPage(scanId, bean.getPage());
	}

	@Override
	public List<String> getRecentStaticVulnTypes(@PathVariable("appId") int appId){
		String userName = SecurityContextHolder.getContext().getAuthentication().getName();
		Integer userId = null;
		User user = userDao.retrieveByName(userName);
		if (user != null)
			userId = user.getId();
		if (userName == null || userId == null)
			return null;
		List<Finding> findings = loadLatestStaticByAppAndUser(appId, userId);
		if(findings == null) return null;
		List<String> cvList = new ArrayList<>();
		for(Finding finding : findings) {
			if (finding == null || finding.getChannelVulnerability() == null || 
					finding.getChannelVulnerability().getCode() == null)
				continue;
			cvList.add(finding.getChannelVulnerability().getCode());
		}
		return removeDuplicates(cvList);
	}
	
	@Override
	public List<String> getRecentDynamicVulnTypes(@PathVariable("appId") int appId){
		String userName = SecurityContextHolder.getContext().getAuthentication().getName();
		Integer userId = null;
		User user = userDao.retrieveByName(userName);
		if (user != null)
			userId = user.getId();
		if (userName == null || userId == null)
			return null;
		List<Finding> findings = loadLatestDynamicByAppAndUser(appId, userId);
		if(findings == null) return null;
		List<String> cvList = new ArrayList<>();
		for(Finding finding : findings) {
			if (finding == null || finding.getChannelVulnerability() == null || 
					finding.getChannelVulnerability().getCode() == null)
				continue;
			cvList.add(finding.getChannelVulnerability().getCode());
		}
		return removeDuplicates(cvList);
	}
	
	@Override
	public List<String> getRecentStaticPaths(@PathVariable("appId") int appId) {
		String userName = SecurityContextHolder.getContext().getAuthentication().getName();
		Integer userId = null;
		User user = userDao.retrieveByName(userName);
		if (user != null)
			userId = user.getId();
		if (userName == null || userId == null)
			return null;
		List<Finding> findings = loadLatestStaticByAppAndUser(appId, userId);
		if(findings == null) return null;
		List<String> pathList = new ArrayList<>();
		for(Finding finding : findings) {
			if (finding == null || finding.getSurfaceLocation() == null || 
					finding.getSurfaceLocation().getPath() == null)
				continue;
			pathList.add(finding.getSurfaceLocation().getPath());
		}
		return removeDuplicates(pathList);
	}
	
	@Override
	public List<String> getRecentDynamicPaths(@PathVariable("appId") int appId) {
		String userName = SecurityContextHolder.getContext().getAuthentication().getName();
		Integer userId = null;
		User user = userDao.retrieveByName(userName);
		if (user != null)
			userId = user.getId();
		if (userName == null || userId == null)
			return null;
		List<Finding> findings = loadLatestDynamicByAppAndUser(appId, userId);
		if(findings == null) return null;
		List<String> pathList = new ArrayList<>();
		for(Finding finding : findings) {
			if (finding == null || finding.getSurfaceLocation() == null || 
					finding.getSurfaceLocation().getPath() == null)
				continue;
			pathList.add(finding.getSurfaceLocation().getPath());
		}
		return removeDuplicates(pathList);
	}
	
	private List<String> removeDuplicates(List<String> stringList) {
		if (stringList == null)
			return new ArrayList<>();
		List<String> distinctStringList = new ArrayList<>();
		for (int i = 0; i < stringList.size(); i++) {
			int j = 0;
			for (; j < i; j++) {
				if (stringList.get(i).equals(stringList.get(j))) {
					break;
				}
			}
			if (j == i)
				distinctStringList.add(stringList.get(i));
		}
		return distinctStringList;
	}
	
	@Override
	public List<ChannelSeverity> getManualSeverities() {
		ChannelType channelType = channelTypeDao.retrieveByName(ScannerType.MANUAL.getFullName());
		return channelSeverityDao.retrieveByChannel(channelType);
	}

	@Override
	public List<String> getAllManualUrls(Integer appId) {
		return findingDao.retrieveManualUrls(appId);
	}
}
