package com.denimgroup.threadfix.service.scans;

public class Difference {
	private String message;
	private SimpleVuln result, target;

	private Difference(String message, SimpleVuln result, SimpleVuln target) {
		this.message = message;
		this.result = result;
		this.target = target;
	}
	
	public static Difference mergeDifference(SimpleVuln csvVuln, SimpleVuln jsonVuln) {
		return new Difference("Vulnerability type was incorrect at line " 
				+ csvVuln.getLineNumber() 
				+ ". Expected type was " + csvVuln.getGenericVuln() 
				+ " and actual type was " + jsonVuln.getGenericVuln(), 
				csvVuln, jsonVuln);
	}
	
	public static Difference fortifyIdDifference(SimpleVuln csvVuln, SimpleVuln jsonVuln) {
		return new Difference("Finding merge was incorrect at line " 
				+ csvVuln.getLineNumber() 
				+ ". Expected Fortify IDs were " + csvVuln.getFortifyNativeIds() 
				+ " and actual Fortify IDs were " + jsonVuln.getFortifyNativeIds(), 
				csvVuln, jsonVuln);
	}

	public String getMessage() {
		return message;
	}
	
	public SimpleVuln getResult() {
		return result;
	}
	
	public SimpleVuln getTarget() {
		return target;
	}
	
	public String toString() { return message; }
}
