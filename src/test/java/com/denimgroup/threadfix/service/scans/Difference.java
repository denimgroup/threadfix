package com.denimgroup.threadfix.service.scans;

public class Difference implements Comparable<Difference> {
	private String message;
	private SimpleVuln result, target;
	private Integer lineNumber;

	private Difference(String message, SimpleVuln csvVuln, SimpleVuln jsonVuln) {
		this.message = message;
		this.result = csvVuln;
		this.target = jsonVuln;
		this.lineNumber = csvVuln.getLineNumber();
	}
	
	public static Difference mergeDifference(SimpleVuln csvVuln, SimpleVuln jsonVuln) {
		return new Difference("Vulnerability type was incorrect at line " 
				+ csvVuln.getLineNumber() 
				+ ". Expected type was " + csvVuln.getGenericVulnId() 
				+ " and actual type was " + jsonVuln.getGenericVulnId(), 
				csvVuln, jsonVuln);
	}
	
	public static Difference fortifyIdDifference(SimpleVuln csvVuln, SimpleVuln jsonVuln) {
		return new Difference("Finding merge was incorrect at line " 
				+ csvVuln.getLineNumber() 
				+ ". Expected Fortify IDs were " + csvVuln.getFortifyNativeIds() 
				+ " and actual Fortify IDs were " + jsonVuln.getFortifyNativeIds(), 
				csvVuln, jsonVuln);
	}
	
	public static Difference pathDifference(SimpleVuln csvVuln, SimpleVuln jsonVuln) {
		return new Difference("Path was incorrect at line " 
				+ csvVuln.getLineNumber() 
				+ ". Expected path was " + csvVuln.getPath() 
				+ " and actual path was " + jsonVuln.getParameter(), 
				csvVuln, jsonVuln);
	}
	
	public SimpleVuln getResult() {
		return result;
	}
	
	public SimpleVuln getTarget() {
		return target;
	}
	
	public String toString() { 
		return message; 
	}
	
	@Override
	public int compareTo(Difference o) {
		if (lineNumber == null || o == null || o.lineNumber == null) {
			return 0;
		}
		return lineNumber.compareTo(o.lineNumber);
	}
}
