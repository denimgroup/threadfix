package com.denimgroup.threadfix.service.scans;

import java.util.ArrayList;
import java.util.List;

class TestResult {
	// These are for finding IDs
	private int correctNoMatch = 0, correctMatch = 0, wrong = 0, missing = 0;
	
	// These are for vuln types
	private int correctCWE = 0, incorrectCWE = 0;
	
	private List<SimpleVuln> 
		incorrectMappingVulns = new ArrayList<>(),
		incorrectCWEVulns = new ArrayList<>();
	
	public void analyze(SimpleVuln vuln, SimpleVuln targetVuln) {
		String targetVulnFortifyId = getFortifyParameter(targetVuln);
		String vulnFortifyId = getFortifyParameter(vuln);
		
		boolean targetVulnEmptyFortify = targetVulnFortifyId == null;
		boolean vulnEmptyFortify = vulnFortifyId == null;
		
		// Compare finding matches
		if (targetVulnEmptyFortify && vulnEmptyFortify) {
			correctNoMatch += 1;
		} else if (!targetVulnEmptyFortify && !vulnEmptyFortify &&
				vulnFortifyId.equals(targetVulnFortifyId)) {
			correctMatch += 1;
		} else {
			wrong += 1;
			incorrectMappingVulns.add(vuln);
		}
		
		// Compare generic vuln IDs
		if (targetVuln.getGenericVulnId().equals(vuln.getGenericVulnId())) {
			correctCWE += 1;
		} else {
			incorrectCWE += 1;
			incorrectCWEVulns.add(vuln);
		}
	}

	public void addMissing(String missingNativeId) {
		missing += 1;
	}
	
	public boolean hasMissing() {
		return missing != 0;
	}
	
	public String toString() {
		StringBuilder builder = new StringBuilder(
			"Total              : " + (correctNoMatch + correctMatch + wrong + missing) +
			"\nCorrect With Match : " + correctMatch + 
			"\nCorrect No Match   : " + correctNoMatch + 
			"\nWrong              : " + wrong + 
			"\nMissing            : " + missing + 
			"\nCWE Matches        : " + correctCWE +
			"\nWrong CWEs         : " + incorrectCWE + "\n");
		
		builder.append("\nIncorrect Mappings:\n");
		for (SimpleVuln vuln : incorrectMappingVulns) {
			builder.append(vuln).append("\n");
		}
		
		builder.append("\nIncorrect CWEs:\n");
		for (SimpleVuln vuln : incorrectCWEVulns) {
			builder.append(vuln).append("\n");
		}
		
		return builder.toString();
	}
	
	public String getFortifyParameter(SimpleVuln vuln) {
		if (vuln == null || vuln.getFortifyNativeIds() == null || vuln.getFortifyNativeIds().isEmpty()) {
			return null;
		}
		
		if (vuln.getFortifyNativeIds().size() > 1) {
			System.out.println("More than one Fortify finding for " + vuln + 
					". This extraction might not be accurate.");
		}
		
		for (String nativeId : vuln.getFortifyNativeIds()) {
			if (nativeId != null && !nativeId.isEmpty() && !nativeId.equals("null")) {
				return nativeId;
			}
		}
		
		return null;
	}
}
