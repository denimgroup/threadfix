package com.denimgroup.threadfix.service.scans;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.denimgroup.threadfix.data.entities.ScannerType;

class SimpleVuln {
	private String path, parameter, genericVuln, genericVulnId, notes, appscanId;
	private Set<String> fortifyNativeIds, appscanIdsToMatch;
	private Integer lineNumber = null;
	
	public static SimpleVuln buildSimpleVuln(String[] args, int lineNumber) {
		if (args.length != 7) {
			throw new IllegalArgumentException();
		}
		
		return new SimpleVuln(args[0], args[1], args[2], args[3], args[4], args[5], args[6], lineNumber);
	}

	public SimpleVuln(String path, String parameter, String genericVulnId,
			String appscanNativeId, String fortifyNativeId, String appscanIds, 
			String notes, int lineNumber) {
		this.path = path;
		this.parameter = parameter;
		this.genericVulnId = genericVulnId;
		this.notes = notes;
		this.lineNumber = lineNumber;
		this.appscanId = appscanNativeId;
		this.fortifyNativeIds  = setContaining(fortifyNativeId);
		this.appscanIdsToMatch = setContaining(appscanIds.split(";"));
		
		if (path == null) {
			this.path = "";
		}
		if (parameter == null) {
			this.parameter = "";
		}
		if (genericVulnId == null) {
			this.genericVuln = "";
		}
	}
	
	public SimpleVuln(JSONObject vulnObject) throws JSONException {
		JSONObject surfaceLocation = vulnObject.getJSONObject("surfaceLocation");
		
		appscanIdsToMatch = new HashSet<>();
		fortifyNativeIds = new HashSet<>();
		
		if (surfaceLocation != null) {
			if (surfaceLocation.has("path")) {
				path = surfaceLocation.getString("path");
			}
			
			if (surfaceLocation.has("parameter")) {
				parameter = surfaceLocation.getString("parameter");
			}
		}
		
		if (vulnObject.getString("calculatedUrlPath") != null) {
			path = vulnObject.getString("calculatedUrlPath");
		}
		
		JSONArray findings = vulnObject.getJSONArray("findings");
		
		JSONObject genericVulnObject = vulnObject.getJSONObject("genericVulnerability");
		
		genericVuln = genericVulnObject.getString("name");
		genericVulnId = genericVulnObject.getString("id");
		
		for (int j = 0; j < findings.length(); j ++) {
			JSONObject finding = findings.getJSONObject(j);
			String channelName = finding.getJSONObject("channelVulnerability")
				.getJSONObject("channelType")
				.getString("name");
			if (channelName.equals(ScannerType.APPSCAN_DYNAMIC.getFullName()))
				appscanIdsToMatch.add(finding.getString("nativeId"));
			else if (channelName.equals(ScannerType.FORTIFY.getFullName()))
				fortifyNativeIds.add(finding.getString("nativeId")); 
		}
	}
	
	private Set<String> setContaining(String... strings) {
		if (strings != null && strings.length != 0 && !"".equals(strings[0].trim())) {
			return new HashSet<>(Arrays.asList(strings));
		} else {
			return new HashSet<>();
		}
	}
	
	public Set<String> getFortifyNativeIds() {
		return fortifyNativeIds;
	}
	
	public String getPath() {
		return path;
	}

	public Set<String> getAppscanIdsToMatch() {
		return appscanIdsToMatch;
	}

	public String getParameter() {
		return parameter;
	}

	public String getGenericVuln() {
		return genericVuln;
	}
	
	public String getGenericVulnId() {
		return genericVulnId;
	}
	
	public String getNotes() {
		return notes;
	}
	
	public Integer getLineNumber() {
		return lineNumber;
	}
	
	public String getAppscanId() {
		return appscanId;
	}
	
	public String toString() {
		return "{ "+ path + ", "  + genericVuln + ", " + parameter + ", " + appscanId + " }";
	}
	
	public boolean equals(Object other) {
		if (other == null || !(other instanceof SimpleVuln)) {
			return false;
		}
		
		SimpleVuln otherVuln = (SimpleVuln) other;
		
		return this.hashCode() == otherVuln.hashCode();
	}
	
	public int hashCode() {
		return (path + "-" + parameter + "-" + genericVuln).hashCode();
	}
}
