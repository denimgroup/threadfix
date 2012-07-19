package com.denimgroup.threadfix.service.channel;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
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
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;

/**
 * This class currently handles JSON output from either the flat JSONArray version
 * or the JSONObject version with the date and other information included.
 * 
 * @author mcollins
 */
public class BrakemanChannelImporter extends AbstractChannelImporter {
	
	boolean hasFindings = false, correctFormat = false, hasDate = false;
	
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
			ChannelSeverityDao channelSeverityDao) {
		this.channelTypeDao = channelTypeDao;
		this.channelVulnerabilityDao = channelVulnerabilityDao;
		this.channelSeverityDao = channelSeverityDao;
		
		this.channelType = channelTypeDao.retrieveByName(ChannelType.BRAKEMAN);
	}
	
	public Calendar getDate(String jsonString) {
		try {
			JSONObject jsonObject = new JSONObject(jsonString);
			JSONObject scanInfo = jsonObject.getJSONObject("scan_info");
			String dateString = scanInfo.getString("timestamp");
			return getCalendarFromString("EEE MMM dd hh:mm:ss Z yyyy",dateString);
		} catch (JSONException e) {
			log.warn("JSON input was probably version 1.");
			return null;
		}
	}
	
	@Override
	public Scan parseInput() {
		if (inputStream == null) {
			return null;
		}
		
		Scan scan = new Scan();
		scan.setFindings(new ArrayList<Finding>());
		scan.setApplicationChannel(applicationChannel);
		
		boolean isVersion2 = false;
		
		String inputString = null;
		
		try {
			inputString = IOUtils.toString(inputStream);
		} catch (IOException e) {
			log.warn("Something went wrong with the input stream. Weird.", e);
		}
		
		if (inputString == null) {
			return null;
		}
		
		JSONObject resultingObject = null;
		
		if (inputString.trim().startsWith("{")) {
			try {
				resultingObject = new JSONObject(inputString);
				if (resultingObject != null) {
					isVersion2 = true;
				}
			} catch (JSONException e) {
				log.info("JSONException raised when trying to create a JSON Object. Probably version 1.");
			}
		}
	
		try {
			JSONArray jsonArray = null;
			
			if (isVersion2) {
				jsonArray = resultingObject.getJSONArray("warnings");
				scan.setImportTime(getDate(inputString));
			} else {
				jsonArray = new JSONArray(inputString);
			}
			
			if (jsonArray == null) {
				return null;
			}
									
			for (int index = 0; index < jsonArray.length(); index++) {
				Object item = jsonArray.get(index);
				
				if (item instanceof JSONObject) {
					JSONObject jsonItem = (JSONObject) item;
					
					String severityCode = String.valueOf(CONFIDENCE_MAP.get(jsonItem.getString("confidence")) +
											SEVERITIES_MAP.get(jsonItem.getString("warning_type")));
					
					String parameter = null;
					
					if (isVersion2) {
						parameter = jsonItem.getString("user_input");
					}
					
					Finding finding = constructFinding(jsonItem.getString("file"),
													   parameter,
													   jsonItem.getString("warning_type"),
													   severityCode);
					
					if (finding != null) {
						finding.setIsStatic(true);
						finding.setNativeId(hashFindingInfo(jsonItem.toString(),null,null));
						
						if (jsonItem.getString("code") != null) {
							DataFlowElement element = new DataFlowElement();
							element.setLineText(jsonItem.getString("code"));
							element.setSourceFileName(jsonItem.getString("file"));
							if (isVersion2) {
								String lineString = jsonItem.getString("line");
								if (!lineString.equals("null")) {
									try {
										element.setLineNumber(Integer.valueOf(lineString));
									} catch (NumberFormatException e) {
										log.error("Non-numeric value found in Brakeman JSON file.");
									}
								}
							}
							finding.setDataFlowElements(Arrays.asList(new DataFlowElement[] {element}));
						}
						
						scan.getFindings().add(finding);
					}
				}
			}
		
		} catch (JSONException e) {
			log.warn(e);
		}
		
		return scan;
	}

	private String getTestStatus() {	    	
    	if (!correctFormat)
    		testStatus = WRONG_FORMAT_ERROR;
    	else if (hasDate)
    		testStatus = checkTestDate();
    	if (SUCCESSFUL_SCAN.equals(testStatus) && !hasFindings)
    		testStatus = EMPTY_SCAN_ERROR;
    	else if (testStatus == null)
    		testStatus = SUCCESSFUL_SCAN;
    	
    	return testStatus;
    }
	
	@Override
	public String checkFile() {
		
		boolean done = false;
		
		byte[] byteArray = null;
		try {
			byteArray = IOUtils.toByteArray(inputStream);
			inputStream = new ByteArrayInputStream(byteArray);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		if (byteArray == null) {
			return WRONG_FORMAT_ERROR;
		}
		
		String jsonString = new String(byteArray);
		
		// Check the first character to avoid a possible exception
		if (jsonString.trim().startsWith("[")) {
			try {
				JSONArray array = new JSONArray(jsonString);
				if (array != null) {
					done = true;
					log.info("Scan is using the old JSON output format.");
					if (array.length() > 0) {
						hasFindings = true;
						JSONObject oneFinding = array.getJSONObject(0);
						if (oneFinding != null) {
							correctFormat = oneFinding.get("location") != null &&
											oneFinding.get("file") != null &&
											oneFinding.get("message") != null &&
											oneFinding.get("confidence") != null &&
											oneFinding.get("code") != null &&
											oneFinding.get("warning_type") != null;										
						}
					}
				}
			} catch (JSONException e) {
				log.warn(e);
			}
		}
		
		// Output Version 2
		// Check the first character to avoid a possible exception
		if (!done && jsonString.trim().startsWith("{")) {
			try {
				JSONObject object = new JSONObject(jsonString);
				if (object != null) {
					log.info("Scan is using the new JSON output format.");
					
					testDate = getDate(jsonString);
					hasDate = testDate != null;
					
					JSONArray array = object.getJSONArray("warnings");
					
					if (array.length() > 0) {
						hasFindings = true;
						JSONObject oneFinding = array.getJSONObject(0);
						if (oneFinding != null) {
							correctFormat = oneFinding.get("location") != null &&
											oneFinding.get("file") != null &&
											oneFinding.get("message") != null &&
											oneFinding.get("confidence") != null &&
											oneFinding.get("code") != null &&
											oneFinding.get("user_input") != null &&
											oneFinding.get("line") != null &&
											oneFinding.get("warning_type") != null;										
						}
					}
				}
			} catch (JSONException e) {
				log.warn(e);
			}
		}

		return getTestStatus();
	}

}
