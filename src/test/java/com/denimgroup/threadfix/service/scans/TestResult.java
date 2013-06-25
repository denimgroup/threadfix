package com.denimgroup.threadfix.service.scans;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

class TestResult {
	// These are for finding IDs
	private int correctNoMatch = 0, correctMatch = 0, wrong = 0;
	private Set<SimpleVuln> missingIds = new HashSet<>();
	
	private List<Difference> differences = new ArrayList<>();
	
	// These are for vuln types + paths
	private int correctCWE = 0, incorrectCWE = 0,
			correctPath = 0, incorrectPath = 0;
		
	private TestResult() {}

	// First draft will only compare the appscan results and which findings they merge to.
	public static TestResult compareResults(List<SimpleVuln> csvResults, List<SimpleVuln> jsonResults) {
		
		Map<String, SimpleVuln> resultMap = new HashMap<>();
		
		for (SimpleVuln csvVuln : csvResults) {
			if (csvVuln.getAppscanNativeIds() != null) {
				for (String nativeId : csvVuln.getAppscanNativeIds()) {
					resultMap.put(nativeId, csvVuln);
				}
			}
		}
		
		TestResult matchResults = new TestResult();
		
		for (SimpleVuln jsonVuln : jsonResults) {
			for (String nativeId : jsonVuln.getAppscanNativeIds()) {
				if (resultMap.containsKey(nativeId)) {
					SimpleVuln csvVuln = resultMap.get(nativeId);
					matchResults.analyze(jsonVuln, csvVuln);
				} else {
					matchResults.addMissing(jsonVuln);
				}
			}
		}
		
		return matchResults;
	}
	
	private void analyze(SimpleVuln jsonVuln, SimpleVuln csvVuln) {
		String csvFortifyId  = getFortifyParameter(csvVuln);
		String jsonFortifyId = getFortifyParameter(jsonVuln);
		
		boolean targetVulnEmptyFortify = csvFortifyId == null;
		boolean vulnEmptyFortify = jsonFortifyId == null;
		
		// Compare finding matches
		if (targetVulnEmptyFortify && vulnEmptyFortify) {
			correctNoMatch += 1;
		} else if (!targetVulnEmptyFortify && !vulnEmptyFortify &&
				jsonFortifyId.equals(csvFortifyId)) {
			correctMatch += 1;
		} else {
			wrong += 1;
			differences.add(Difference.fortifyIdDifference(csvVuln, jsonVuln));
		}
		
		// Compare generic vuln IDs
		if (csvVuln.getGenericVulnId().equals(jsonVuln.getGenericVulnId())) {
			correctCWE += 1;
		} else {
			incorrectCWE += 1;
			differences.add(Difference.mergeDifference(csvVuln, jsonVuln));
		}
		
		// Compare paths
		if (csvVuln.getPath().equals(jsonVuln.getPath())) {
			correctPath += 1;
		} else {
			differences.add(Difference.pathDifference(csvVuln, jsonVuln));
			incorrectPath += 1;
		}
	}

	public void addMissing(SimpleVuln vuln) {
		missingIds.add(vuln);
	}
	
	public boolean hasMissing() {
		return missingIds.size() != 0;
	}
	
	public String toString() {
		StringBuilder builder = new StringBuilder(
			"Total              : " + (correctNoMatch + correctMatch + wrong + missingIds.size()) +
			"\nCorrect With Match : " + correctMatch + 
			"\nCorrect No Match   : " + correctNoMatch + 
			"\nWrong              : " + wrong + 
			"\nMissing            : " + missingIds.size() + 
			"\nCWE Matches        : " + correctCWE +
			"\nWrong CWEs         : " + incorrectCWE + 
			"\nPath Matches       : " + correctPath +
			"\nWrong Paths        : " + incorrectPath + 
			"\n");
		
		if (missingIds.size() != 0) {
			addItemsToBuilder("\nMissing ids (get your native IDs right first):\n", missingIds, builder);
		} else {
			Collections.sort(differences);
			addItemsToBuilder("\nProblems:\n", differences, builder);
		}
		
		return builder.toString();
	}
	
	private void addItemsToBuilder(String name, Iterable<?> items, StringBuilder builder) {
		builder.append(name);
		
		for (Object item : items) {
			builder.append(item).append("\n");
		}
	}
	
	private String getFortifyParameter(SimpleVuln vuln) {
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
