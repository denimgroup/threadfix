package com.denimgroup.threadfix.service;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.denimgroup.threadfix.data.entities.Finding;

public class StaticFindingPathUtils {

	// TODO figure out what to do for dynamic scans when we update, right now we
	// discard the original path information
	public static String getFindingPathWithRoot(Finding finding,
			String applicationRoot) {
		if (finding == null || applicationRoot == null)
			return null;

		String sourceFileName = null;

		if (!finding.getIsStatic() && finding.getSurfaceLocation() != null
				&& finding.getSurfaceLocation() != null)
			sourceFileName = finding.getSurfaceLocation().getPath();
		else if (finding.getIsStatic())
			sourceFileName = getStaticFindingPathGuess(finding);

		if (sourceFileName == null)
			return null;

		if (sourceFileName.contains("\\"))
			sourceFileName = sourceFileName.replace("\\", "/");

		if (sourceFileName.toLowerCase().contains(
				"/" + applicationRoot.toLowerCase())) {

			int index = sourceFileName.toLowerCase().indexOf(
					"/" + applicationRoot.toLowerCase());

			return sourceFileName.substring(index);
		}

		return null;
	}

	// this method finds the whole path up to and including any of the
	// extensions in suffixVals, the prefix will be taken out later
	public static String getStaticFindingPathGuess(Finding finding) {
		String path = null;
		String[] suffixVals = { "aspx", "asp", "jsp", "php", "html", "htm",
				"java", "cs", "config", "js", "cgi", "ascx" };

		if (finding != null
				&& finding.getIsStatic()
				&& finding.getDataFlowElements() != null
				&& finding.getDataFlowElements().size() != 0
				&& finding.getDataFlowElements().get(0) != null
				&& finding.getDataFlowElements().get(0).getSourceFileName() != null) {
			path = finding.getDataFlowElements().get(0).getSourceFileName();

			for (String val : suffixVals) {
				if (!path.contains(val))
					continue;

				String temp = getRegexResult(path, "(.+\\." + val + ")");
				if (temp != null) {
					path = temp;
					break;
				}
			}
		}
		return path;
	}

	private static String getRegexResult(String targetString, String regex) {
		if (targetString == null || targetString.isEmpty() || regex == null
				|| regex.isEmpty())
			return null;

		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(targetString);

		if (matcher.find())
			return matcher.group(1);
		else
			return null;
	}
	
}
