package com.denimgroup.threadfix.service.channel;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;

import com.denimgroup.threadfix.data.dao.ChannelSeverityDao;
import com.denimgroup.threadfix.data.dao.ChannelTypeDao;
import com.denimgroup.threadfix.data.dao.ChannelVulnerabilityDao;
import com.denimgroup.threadfix.data.dao.VulnerabilityMapLogDao;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;

public class BrakemanChannelImporter extends AbstractChannelImporter {
	
	// This is a hybrid confidence / vuln type mix. We may not end up keeping this.
	private static final Map<String, Integer> SEVERITIES_MAP = new HashMap<String, Integer>();
	static {
		SEVERITIES_MAP.put("Cross Site Scripting", 3);
		SEVERITIES_MAP.put("Response Splitting", 2);
		SEVERITIES_MAP.put("Nested Attributes", 1);
		SEVERITIES_MAP.put("Mass Assignment", 2);
		SEVERITIES_MAP.put("Format Validation", 1);
		SEVERITIES_MAP.put("Redirect", 3);
		SEVERITIES_MAP.put("Command Injection", 3);
		SEVERITIES_MAP.put("Dynamic Render Path", 2);
		SEVERITIES_MAP.put("Mail Link", 2);
		SEVERITIES_MAP.put("SQL Injection", 3);
		SEVERITIES_MAP.put("Session Setting", 3);
		SEVERITIES_MAP.put("Dangerous Send", 3);
		SEVERITIES_MAP.put("File Access", 3);
		SEVERITIES_MAP.put("Basic Auth", 1);
		SEVERITIES_MAP.put("Attribute Restriction", 1);
		SEVERITIES_MAP.put("Dangerous Eval", 2);
		SEVERITIES_MAP.put("Default Routes", 1);
		SEVERITIES_MAP.put("Cross-Site Request Forgery", 2);
	}
	
	// This is a hybrid confidence / vuln type mix. We may not end up keeping this.
	private static final Map<String, Integer> CONFIDENCE_MAP = new HashMap<String, Integer>();
	static {
		CONFIDENCE_MAP.put("High", 2);
		CONFIDENCE_MAP.put("Medium", 1);
		CONFIDENCE_MAP.put("Weak", 0);
	}

	@Autowired
	public BrakemanChannelImporter(ChannelTypeDao channelTypeDao,
			ChannelVulnerabilityDao channelVulnerabilityDao,
			VulnerabilityMapLogDao vulnerabilityMapLogDao,
			ChannelSeverityDao channelSeverityDao) {
		this.channelTypeDao = channelTypeDao;
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.vulnerabilityMapLogDao = vulnerabilityMapLogDao;
		this.channelSeverityDao = channelSeverityDao;
		
		this.channelType = channelTypeDao.retrieveByName(ChannelType.BRAKEMAN);
	}
	
	@Override
	public Scan parseInput() {
		if (inputStream == null) {
			return null;
		}
		
		Scan scan = new Scan();
		scan.setFindings(new ArrayList<Finding>());
		scan.setApplicationChannel(applicationChannel);
	
		try {
			JSONArray jsonArray = new JSONArray(IOUtils.toString(inputStream));
						
			for (int index = 0; index < jsonArray.length(); index++) {
				Object item = jsonArray.get(index);
				
				if (item instanceof JSONObject) {
					JSONObject jsonItem = (JSONObject) item;
					
					String severityCode = String.valueOf(CONFIDENCE_MAP.get(jsonItem.getString("confidence")) +
											SEVERITIES_MAP.get(jsonItem.getString("warning_type")));
					
					Finding finding = constructFinding(jsonItem.getString("file"),
													   null,
													   jsonItem.getString("warning_type"),
													   severityCode);
					
					if (finding != null) {
						finding.setIsStatic(true);
						finding.setNativeId(hashFindingInfo(jsonItem.toString(),null,null));
						
						if (jsonItem.getString("code") != null) {
							DataFlowElement element = new DataFlowElement();
							element.setLineText(jsonItem.getString("code"));
							element.setSourceFileName(jsonItem.getString("file"));
							finding.setDataFlowElements(Arrays.asList(new DataFlowElement[] {element}));
						}
						
						scan.getFindings().add(finding);
					}
				}
			}
		
		} catch (JSONException e) {
			log.warn(e);
		} catch (IOException e) {
			log.warn(e);
		}
		
		return scan;
	}

	@Override
	public String checkFile() {
		return SUCCESSFUL_SCAN;
	}

}
