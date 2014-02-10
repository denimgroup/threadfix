////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

package com.denimgroup.threadfix.service.scans;

public class Difference implements Comparable<Difference> {
	private final String expected, actual;
	private final Integer lineNumber;
	private final Type type;
	
	private enum Type {
		VULN_TYPE("CWE"), FINDINGS("Finding"), PATH("Path"), PARAMETER("Parameter");
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
	
	public static Difference cweDifference(SimpleVuln csvVuln, SimpleVuln jsonVuln) {
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
	
	public static Difference parameterDifference(SimpleVuln csvVuln, SimpleVuln jsonVuln) {
		return new Difference(Type.PARAMETER, csvVuln.getLineNumber(),
				csvVuln.getParameter(),
				jsonVuln.getParameter());
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
