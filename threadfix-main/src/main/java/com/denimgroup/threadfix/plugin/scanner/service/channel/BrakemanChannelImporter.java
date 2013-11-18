package com.denimgroup.threadfix.plugin.scanner.service.channel;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import net.xeoh.plugins.base.annotations.PluginImplementation;

import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.denimgroup.threadfix.data.entities.DataFlowElement;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.webapp.controller.ScanCheckResultBean;

/**
 * This class currently handles JSON output from either the flat JSONArray version
 * or the JSONObject version with the date and other information included.
 * 
 * @author mcollins
 */
@PluginImplementation
public class BrakemanChannelImporter extends AbstractChannelImporter {

	@Override
	public String getType() {
		return ScannerType.BRAKEMAN.getFullName();
	}
	
	boolean hasFindings = false, correctFormat = false, hasDate = false;
	
	// This is a hybrid confidence / vuln type mix. We may not end up keeping this.
	private static final Map<String, Integer> SEVERITIES_MAP = new HashMap<>();
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
		SEVERITIES_MAP.put("Remote Code Execution", 3);
		SEVERITIES_MAP.put("Denial of Service", 2);
		SEVERITIES_MAP.put("Authentication", 1);
	}
	
	// This is a hybrid confidence / vuln type mix. We may not end up keeping this.
	private static final Map<String, Integer> CONFIDENCE_MAP = new HashMap<>();
	static {
		CONFIDENCE_MAP.put("High", 2);
		CONFIDENCE_MAP.put("Medium", 1);
		CONFIDENCE_MAP.put("Weak", 0);
	}

	public BrakemanChannelImporter() {
		super(ScannerType.BRAKEMAN.getFullName());
	}
	
	public Calendar getDate(String jsonString) {
		try {
			JSONObject jsonObject = new JSONObject(jsonString);
			JSONObject scanInfo = jsonObject.getJSONObject("scan_info");
			String dateString = scanInfo.getString("timestamp");
			return getCalendarFromString("EEE MMM dd hh:mm:ss Z yyyy",dateString);
		} catch (JSONException e) {
			try {
				JSONObject jsonObject = new JSONObject(jsonString);
				JSONObject scanInfo = jsonObject.getJSONObject("scan_info");
				String dateString = scanInfo.getString("start_time");
				return getCalendarFromString("yyyy-MM-dd hh:mm:ss Z",dateString);	
			} catch (JSONException f){
				log.warn("JSON input was probably version 1.", f);
				return null;
			}
		}
	}
	
	// TODO refactor this 130-line method into a few 30 line methods
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
		} finally {
			closeInputStream(inputStream);
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
				log.info("JSONException raised when trying to create a JSON Object. Probably version 1.", e);
			}
		}
		
		if (resultingObject == null) {
			log.error("Unable to retrieve JSONObject from uploaded file. Exiting.");
			return null;
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
				
				log.debug("Checking item[" + index + "] in the jsonArray");
				
				Object item = jsonArray.get(index);
				
				if (item instanceof JSONObject) {
					JSONObject jsonItem = (JSONObject) item;
					
					String jsConfidence = jsonItem.getString("confidence");
					log.debug("JSON confidence value is " + jsConfidence);
					String jsWarningType = jsonItem.getString("warning_type");
					log.debug("JSON warning_type is " + jsWarningType);
					
					Integer confidence = CONFIDENCE_MAP.get(jsConfidence);
					log.debug("Mapped confidence is " + confidence);
					Integer severity = SEVERITIES_MAP.get(jsWarningType);
					log.debug("Mapped severity for warning_type " + jsWarningType + " is " + severity);
					
					//	Make sure we got valid values back. As the Brakeman JSON file format advances over
					//	time they might add vulnerability types or confidence values that we have not
					//	anticipated and we want to be able to at least partially fight through.
					
					if(confidence == null) {
						log.warn("Got a null ThreadFix confidence for JSON confidence of " + jsConfidence);
						continue;
					} else if(severity == null) {
						log.warn("Got a null ThreadFix severity for JSON warning_type of " + jsWarningType);
						continue;
					}
					
					String severityCode = String.valueOf(confidence + severity);
					
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
										log.error("Non-numeric value found in Brakeman JSON file.", e);
									}
								}
							}
							finding.setDataFlowElements(Arrays.asList(element));
						}
						
						scan.getFindings().add(finding);
					}
				} else {
					log.debug("Got a non-JSONObject object: " + item);
				}
			}
		
		} catch (JSONException e) {
			log.warn("Encountered JSONException.", e);
		}
		
		return scan;
	}

	private ScanImportStatus getTestStatus() {
    	if (!correctFormat) {
			testStatus = ScanImportStatus.WRONG_FORMAT_ERROR;
		} else if (hasDate) {
			testStatus = checkTestDate();
		}
    	if (ScanImportStatus.SUCCESSFUL_SCAN.equals(testStatus) && !hasFindings) {
			testStatus = ScanImportStatus.EMPTY_SCAN_ERROR;
		} else if (testStatus == null) {
			testStatus = ScanImportStatus.SUCCESSFUL_SCAN;
		}
    	
    	return testStatus;
    }
	
	@Override
	public ScanCheckResultBean checkFile() {
		
		boolean done = false;
		
		byte[] byteArray = null;
		try {
			byteArray = IOUtils.toByteArray(inputStream);
			closeInputStream(inputStream);
			inputStream = new ByteArrayInputStream(byteArray);
		} catch (IOException e) {
			log.error("Problems manipulating input stream and byte array.", e);
		}
		
		if (byteArray == null) {
			return new ScanCheckResultBean(ScanImportStatus.WRONG_FORMAT_ERROR);
		}
		
		String jsonString = new String(byteArray);
		
		// Check the first character to avoid a possible exception
		if (jsonString.trim().startsWith("[")) {
			try {
				JSONArray array = new JSONArray(jsonString);
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
			} catch (JSONException e) {
				log.warn("Encountered JSONException.", e);
			}
		}
		
		// Output Version 2
		// Check the first character to avoid a possible exception
		if (!done && jsonString.trim().startsWith("{")) {
			try {
				JSONObject object = new JSONObject(jsonString);
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
			} catch (JSONException e) {
				log.warn("Encountered JSONException.", e);
			}
		}

		return new ScanCheckResultBean(getTestStatus(), testDate);
	}

}
