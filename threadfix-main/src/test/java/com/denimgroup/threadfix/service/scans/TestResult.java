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
	private int 
			correctCWE = 0, incorrectCWE = 0,
			correctPath = 0, incorrectPath = 0,
			correctParam = 0, incorrectParam = 0,
			correctAppscan = 0, incorrectAppscan = 0;
		
	private TestResult() {}

	// First draft will only compare the appscan results and which findings they merge to.
	public static TestResult compareResults(List<SimpleVuln> csvResults, List<SimpleVuln> jsonResults) {
		
		Map<String, SimpleVuln> resultMap = new HashMap<>();
		
		for (SimpleVuln csvVuln : csvResults) {
			if (csvVuln.getAppscanId() != null) {
				resultMap.put(csvVuln.getAppscanId(), csvVuln);
			}
		}
		
		TestResult matchResults = new TestResult();
		
		for (SimpleVuln jsonVuln : jsonResults) {
			for (String nativeId : jsonVuln.getAppscanIdsToMatch()) {
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
		
		if (csvVuln.getAppscanIdsToMatch() != null &&
				jsonVuln.getAppscanIdsToMatch() != null) {
			// we may want to count the empty / empty and has all / has all separately
			if (csvVuln.getAppscanIdsToMatch().isEmpty() && jsonVuln.getAppscanIdsToMatch().size() == 1) {
				correctAppscan += 1;
			} else if (jsonVuln.getAppscanIdsToMatch().containsAll(csvVuln.getAppscanIdsToMatch())) {
				correctAppscan += 1;
			} else {
				incorrectAppscan += 1;
			}
		} else {
			incorrectAppscan += 1; // shouldn't ever get here
		}
		
		// Compare generic vuln IDs
		if (csvVuln.getGenericVulnId().equals(jsonVuln.getGenericVulnId())) {
			correctCWE += 1;
		} else {
			incorrectCWE += 1;
			differences.add(Difference.cweDifference(csvVuln, jsonVuln));
		}
		
		// Compare paths
		if (csvVuln.getPath().equals(jsonVuln.getPath())) {
			correctPath += 1;
		} else {
			differences.add(Difference.pathDifference(csvVuln, jsonVuln));
			incorrectPath += 1;
		}
		
		// Compare parameters
		if (csvVuln.getParameter().equals(jsonVuln.getParameter())) {
			correctParam += 1;
		} else {
			differences.add(Difference.parameterDifference(csvVuln, jsonVuln));
			incorrectParam += 1;
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
			"\nParameter Matches  : " + correctParam +
			"\nWrong Parameter    : " + incorrectParam + 
			"\nAppscan Matches    : " + correctAppscan +
			"\nWrong Appscan      : " + incorrectAppscan + 
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
	
	// format is total, correctly merged, correct path, correct param, correctCWE
	public String getCsvLine() {
		return "," + (wrong + correctMatch + correctNoMatch) + 
				"," + (correctMatch + correctNoMatch) +
				"," + (correctPath) +
				"," + (correctParam) +
				"," + (correctCWE) +
				"," + (correctAppscan)
				;
	}
}
