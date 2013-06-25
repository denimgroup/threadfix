package com.denimgroup.threadfix.service.scans;

public class Difference implements Comparable<Difference> {
	private final String expected, actual;
	private final Integer lineNumber;
	private final Type type;
	
	private enum Type {
		VULN_TYPE("CWE"), FINDINGS("Finding"), PATH("Path");
		private String name;
		public String toString() { return name; }
		Type(String name) { this.name = name; }
	}

	private Difference(Type type, Integer lineNumber, String expected, String actual) {
		this.expected = expected;
		this.actual = actual;
		this.lineNumber = lineNumber;
		this.type = type;
	}
	
	public static Difference mergeDifference(SimpleVuln csvVuln, SimpleVuln jsonVuln) {
		return new Difference(Type.VULN_TYPE, csvVuln.getLineNumber(),
				csvVuln.getGenericVulnId(),
				jsonVuln.getGenericVulnId());
	}
	
	public static Difference fortifyIdDifference(SimpleVuln csvVuln, SimpleVuln jsonVuln) {
		return new Difference(Type.FINDINGS, csvVuln.getLineNumber(),
				csvVuln.getFortifyNativeIds().toString(),
				jsonVuln.getFortifyNativeIds().toString());
	}
	
	public static Difference pathDifference(SimpleVuln csvVuln, SimpleVuln jsonVuln) {
		return new Difference(Type.PATH, csvVuln.getLineNumber(),
				csvVuln.getPath(),
				jsonVuln.getPath());
	}
	
	public String toString() { 
		return lineNumber + ". " + type + " was incorrect. " + 
				"Expected: " + expected + 
				", actual: " + actual; 
	}
	
	@Override
	public int compareTo(Difference o) {
		if (lineNumber == null || o == null || o.lineNumber == null) {
			return 0;
		}
		return lineNumber.compareTo(o.lineNumber);
	}
}
