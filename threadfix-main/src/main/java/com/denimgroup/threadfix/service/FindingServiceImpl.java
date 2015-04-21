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

import com.denimgroup.threadfix.data.dao.*;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.importer.util.IntegerUtils;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.beans.TableSortBean;
import com.denimgroup.threadfix.webapp.utils.MessageConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.PathVariable;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.data.entities.GenericSeverity.REVERSE_MAP;
import static com.denimgroup.threadfix.webapp.controller.rest.AddFindingRestController.*;

@Service
@Transactional(readOnly = false) // used to be true
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
	public void validateManualFinding(Finding finding, BindingResult result, boolean isStatic) {

		if (finding == null || ((finding.getChannelVulnerability() == null) || 
				(finding.getChannelVulnerability().getCode() == null) ||
				(finding.getChannelVulnerability().getCode().isEmpty()))) {
			result.rejectValue("channelVulnerability.code", "errors.required", new String [] { "Vulnerability" }, null);
			return;
		} else {
            String code = finding.getChannelVulnerability().getCode();
            if (code.indexOf("(CWE")<0)
                finding.getChannelVulnerability().setCode(code.trim());
            else finding.getChannelVulnerability().setCode(code.substring(0, code.indexOf("(CWE")).trim());

            if (!channelVulnerabilityDao.isValidManualName(finding.getChannelVulnerability().getCode())) {

				boolean wasNumeric = false;

				// Try to parse an ID from the string and use that
				ChannelVulnerability newChannelVuln = null;

                Integer requestedId = IntegerUtils.getIntegerOrNull(finding.getChannelVulnerability().getCode());

                if (requestedId != null) {
                    wasNumeric = true;
                    String cweName = null;
                    ChannelType manualType = null;
                    GenericVulnerability genericVulnerability = genericVulnerabilityDao.retrieveByDisplayId(requestedId);
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

		if (finding.getLongDescription() == null ||
				finding.getLongDescription().trim().isEmpty()) {
			result.rejectValue("longDescription", "errors.required", new String [] { "Description" }, null);
		}

		FieldError originalError = result.getFieldError("dataFlowElements[0].lineNumber");
		if (originalError != null && originalError.getDefaultMessage()
				.startsWith("Failed to convert property value of type " +
						"'java.lang.String' to required type 'int'")) {
			result.rejectValue("dataFlowElements", "errors.invalid", new String [] { "Line number" }, null);
		}

        if (isStatic) {
            if (finding.getDataFlowElements() == null
                    || finding.getDataFlowElements().get(0) == null
                    || finding.getDataFlowElements().get(0).getSourceFileName() == null
                    || finding.getDataFlowElements().get(0).getSourceFileName().trim().isEmpty()) {
                result.rejectValue("sourceFileLocation", MessageConstants.ERROR_REQUIRED, new String[]{"Source File"}, null);
            }
        } else {    // dynamic
            if (finding.getSurfaceLocation() == null ||
                    ( (finding.getSurfaceLocation().getParameter() == null || finding.getSurfaceLocation().getParameter().trim().isEmpty()) &&
                            (finding.getSurfaceLocation().getPath() == null || finding.getSurfaceLocation().getPath().trim().isEmpty()) )) {
                result.rejectValue("surfaceLocation.parameter", null, null, "Input at least URL or Parameter");
            }
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
		ChannelSeverity channelSeverity = getChannelSeverity(severity);
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
			
			DataFlowElement element = new DataFlowElement(filePath, IntegerUtils.getPrimitive(lineNumber), lineText, 0);
			element.setColumnNumber(IntegerUtils.getPrimitive(column));
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
    @Nonnull
    public String checkRequestForFindingParameters(@Nonnull HttpServletRequest request) {
		String longDescription = request.getParameter("longDescription");
		if (longDescription == null || longDescription.trim().equals("") || 
				longDescription.length() > Finding.LONG_DESCRIPTION_LENGTH) {
			return INVALID_DESCRIPTION;
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
			return INVALID_VULN_NAME;
		}

		String severity = request.getParameter("severity");
		ChannelSeverity channelSeverity = null;
		if (severity != null) {
			channelSeverity = getChannelSeverity(severity);
		}

		if (severity == null || channelSeverity == null) {
			return INVALID_SEVERITY;
		}
		
		return PASSED_CHECK;
	}

	private ChannelSeverity getChannelSeverity(String severity) {
		return channelSeverityDao
            .retrieveByCode(
					channelTypeDao.retrieveByName(ScannerType.MANUAL.getFullName()),
					REVERSE_MAP.get(severity));
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
	public List<Finding> getUnmappedFindingTable(TableSortBean bean) {
		return findingDao.retrieveUnmappedFindingsByPage(bean.getPage(), bean.getApplicationId());
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
		List<String> cvList = list();
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
		List<String> cvList = list();
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
			return list();
		List<Finding> findings = loadLatestStaticByAppAndUser(appId, userId);
		if(findings == null) return null;
		List<String> pathList = list();
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
			return list();
		List<Finding> findings = loadLatestDynamicByAppAndUser(appId, userId);
		if(findings == null) return null;
		List<String> pathList = list();
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
			return list();
		List<String> distinctStringList = list();
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

	@Override
	public long getTotalUnmappedFindings() {
		return findingDao.getTotalUnmappedFindings();
	}
}
