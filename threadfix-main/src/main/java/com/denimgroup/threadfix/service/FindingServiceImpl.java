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
import com.denimgroup.threadfix.importer.update.impl.ChannelVulnerabilityUpdater;
import com.denimgroup.threadfix.importer.util.IntegerUtils;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.beans.TableSortBean;
import com.denimgroup.threadfix.service.enterprise.EnterpriseTest;
import com.denimgroup.threadfix.service.translator.FindingProcessorFactory;
import com.denimgroup.threadfix.util.FileTree;
import com.denimgroup.threadfix.util.SimilarityCalculator;
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
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.CollectionUtils.set;
import static com.denimgroup.threadfix.data.entities.GenericSeverity.REVERSE_MAP;
import static com.denimgroup.threadfix.webapp.controller.rest.AddFindingRestController.*;

@Service
@Transactional(readOnly = false) // used to be true
public class FindingServiceImpl implements FindingService {

	@Autowired
	private FindingDao findingDao = null;
	@Autowired
	private ChannelVulnerabilityDao channelVulnerabilityDao = null;
	@Autowired
	private GenericVulnerabilityDao genericVulnerabilityDao = null;
	@Autowired
	private UserDao userDao = null;
	@Autowired
	private ChannelTypeDao channelTypeDao = null;
	@Autowired
	private ChannelSeverityDao channelSeverityDao = null;
	@Autowired
	private GenericSeverityDao genericSeverityDao = null;
	@Autowired
	private ChannelVulnerabilityUpdater channelVulnerabilityUpdater;

	private final SanitizedLogger log = new SanitizedLogger(FindingServiceImpl.class);

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

				ChannelType manualType = channelTypeDao.retrieveByName(ScannerType.MANUAL.getDisplayName());

				if (manualType != null) {
					if (requestedId != null) {
						wasNumeric = true;
						String cweName;

						GenericVulnerability genericVulnerability = genericVulnerabilityDao.retrieveByDisplayId(requestedId);
						if (genericVulnerability != null) {
							cweName = genericVulnerability.getName();
							if (cweName != null) {
								newChannelVuln = channelVulnerabilityDao.retrieveByName(manualType, cweName);
								if (newChannelVuln == null) {
									// it is supposed to have mapping here, so we will add a new manual channel vuln mapping
									newChannelVuln = channelVulnerabilityUpdater.createNewChannelVulnerability(cweName, cweName,
											genericVulnerability, manualType);
								}
							}
						}

					} else { // try to create new manual channel vuln mapping
						GenericVulnerability genericVulnerability = genericVulnerabilityDao.retrieveByName(finding.getChannelVulnerability().getCode());
						if (genericVulnerability != null) {
							newChannelVuln = channelVulnerabilityUpdater.createNewChannelVulnerability(finding.getChannelVulnerability().getCode(),
									finding.getChannelVulnerability().getCode(),
									genericVulnerability, manualType);
						}
					}
				}

				if (newChannelVuln != null) {
					// id lookup success, set the name to the actual name instead of the id.
					finding.getChannelVulnerability().setCode(newChannelVuln.getCode());
				} else {
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
							channelTypeDao.retrieveByName(ScannerType.MANUAL.getDisplayName()),
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
						channelTypeDao.retrieveByName(ScannerType.MANUAL.getDisplayName()),
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
	public List<Map<String, Object>> getManualSeverities() {
		ChannelType channelType = channelTypeDao.retrieveByName(ScannerType.MANUAL.getDisplayName());
		List<ChannelSeverity> channelSeverities = channelSeverityDao.retrieveByChannel(channelType);

		List<Map<String, Object>> returnList = list();
		Map<String, String> customNameMap = getCustomNameMap();

		for (ChannelSeverity severity : channelSeverities) {

			if (!GenericSeverity.NUMERIC_MAP.containsKey(severity.getName())) {
				continue;
			}

			// kinda gross, avoids some typing errors though
			Map<String, Object> map = map();
			map.putAll(map(
					"id", severity.getId(),
					"name", severity.getName(),
					"displayName", customNameMap.get(severity.getName())
			));
			returnList.add(map);
		}

		return returnList;
	}

	private Map<String, String> getCustomNameMap() {

		List<GenericSeverity> genericSeverities = genericSeverityDao.retrieveAll();

		Map<String, String> returnMap = map();

		for (GenericSeverity genericSeverity : genericSeverities) {
			returnMap.put(genericSeverity.getName(), genericSeverity.getDisplayName());
		}

		return returnMap;
	}

	@Override
	public List<String> getAllManualUrls(Integer appId) {
		return findingDao.retrieveManualUrls(appId);
	}

	@Override
	public long getTotalUnmappedFindings() {
		return findingDao.getTotalUnmappedFindings();
	}

	@Override
	public String getUnmappedTypesAsString() {
		List<Finding> unmappedFindings = findingDao.getUnmappedFindings();
		StringBuilder sb = new StringBuilder();
		Map<String, Set<String>> unmappedTypes = new HashMap<>();

		for (Finding unmappedFinding : unmappedFindings) {
			String scanName = unmappedFinding.getScan().getApplicationChannel().getChannelType().getName();
			String vulnName = unmappedFinding.getChannelVulnerability().getName();
			if (unmappedTypes.containsKey(scanName)) {
				Set<String> vulnTypes = unmappedTypes.get(scanName);
				vulnTypes.add(vulnName);
				unmappedTypes.put(scanName, vulnTypes);
			} else {
				Set<String> vulnTypes = new HashSet<>();
				vulnTypes.add(vulnName);
				unmappedTypes.put(scanName, vulnTypes);
			}
		}

		for (String scanName : unmappedTypes.keySet()) {
			List<String> vulnTypes = new ArrayList(unmappedTypes.get(scanName));
			Collections.sort(vulnTypes);

			sb.append(scanName).append("\n");
			for (String vulnType : vulnTypes) {
				sb.append(vulnType).append("\n");
			}
			sb.append("\n");
		}

		try {
			return URLEncoder.encode(sb.toString(), "UTF-8").replaceAll("\\+", "%20");
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException("UTF-8 was not supported.", e);
		}



	}

	@Override
	public List<Finding> loadByGenericSeverityAndChannelType(GenericSeverity genericSeverity, ChannelType channelType) {
		return findingDao.retrieveByGenericSeverityAndChannelType(genericSeverity, channelType);
	}

	@Override
	public Map<String, String> getFilesWithVulnerabilities(Finding finding) {

		Map<String, String> fileMap = map();

        if (EnterpriseTest.isEnterprise()) {
			if(finding.getVulnerability() == null){
				return fileMap;
			}

            if (!hasSourceCode(finding))
                return fileMap;

			File rootDir = FindingProcessorFactory.getRootFile(finding.getVulnerability().getApplication());
            List<DataFlowElement> dataFlowElements = finding.getDataFlowElements();
            Set<String> relFilePaths = set();

            if (dataFlowElements != null && !dataFlowElements.isEmpty()) {
                for (DataFlowElement dataFlowElement : dataFlowElements) {
                    relFilePaths.add(dataFlowElement.getSourceFileName());
                }
            } else if (finding.getSourceFileLocation() != null && !finding.getSourceFileLocation().isEmpty()) {
                relFilePaths.add(finding.getSourceFileLocation());

            } else if (finding.getCalculatedFilePath() != null && !finding.getCalculatedFilePath().isEmpty()) {
                relFilePaths.add(finding.getCalculatedFilePath());
            } else {
                return fileMap;
            }

            FileTree fileTree = new FileTree();
            fileTree.walk(rootDir);
            List<String> allAbsoluteFilePaths = fileTree.getResultFilePaths();

            for (String relFilePath : relFilePaths) {
                String absoluteFilePath = SimilarityCalculator.findMostSimilarFilePath(relFilePath, allAbsoluteFilePaths);
                if (absoluteFilePath != null) {

                    StringBuilder fileOutput = new StringBuilder();

                    try (BufferedReader br = new BufferedReader(new FileReader(absoluteFilePath))) {
                        String line;
                        while ((line = br.readLine()) != null) {
                            fileOutput.append(line + System.lineSeparator());
                        }
                    } catch (IOException e) {
                        log.error(e.getMessage());
                    }

                    fileMap.put(relFilePath, fileOutput.toString());
                }
            }
        }

		return fileMap;
	}

	@Override
	public Map<String, Set<Integer>> getFilesWithLineNumbers(Finding finding) {

		Map<String, Set<Integer>> fileLineNumMap = map();

        if (EnterpriseTest.isEnterprise()) {
            List<DataFlowElement> dataFlowElements = finding.getDataFlowElements();

            if (dataFlowElements != null && !dataFlowElements.isEmpty()) {
                for (DataFlowElement dataFlowElement : dataFlowElements) {

                    String sourceFileName = dataFlowElement.getSourceFileName();
                    Set<Integer> lineNumberList = fileLineNumMap.get(dataFlowElement.getSourceFileName());

                    if (lineNumberList == null) {
                        lineNumberList = set(dataFlowElement.getLineNumber());
                    } else {
                        lineNumberList.add(dataFlowElement.getLineNumber());
                    }

                    fileLineNumMap.put(sourceFileName, lineNumberList);
                }
            }
        }

		return fileLineNumMap;
	}

	@Override
	public boolean hasSourceCode(Finding finding) {
		File rootDir = FindingProcessorFactory.getRootFile(finding.getVulnerability().getApplication());

		boolean hasSourceCode = false;

		if (rootDir != null) {
			if (rootDir.isDirectory()){
				hasSourceCode = true;
			}
		}

		return hasSourceCode;
	}
}
