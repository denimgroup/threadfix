package com.denimgroup.threadfix.service.framework;

public class SpringControllerEndpoint {

	private final String rawFilePath, rawUrlPath;
	private final int startLineNumber, endLineNumber;
	
	private String cleanedFilePath = null, cleanedUrlPath = null;
	
	private String fileRoot;
	
	public SpringControllerEndpoint(String filePath, String urlPath, int startLineNumber, int endLineNumber) {
		this.rawFilePath = filePath;
		this.rawUrlPath = urlPath;
		this.startLineNumber = startLineNumber;
		this.endLineNumber = endLineNumber;
	}
	
	public String getRawFilePath() {
		return rawFilePath;
	}

	public String getRawUrlPath() {
		return rawUrlPath;
	}

	public String getCleanedFilePath() {
		if (cleanedFilePath == null && fileRoot != null && 
				rawFilePath != null && rawFilePath.contains(fileRoot)) {
			cleanedFilePath = rawFilePath.substring(fileRoot.length());
		}
		
		return cleanedFilePath;
	}
	
	public void setFileRoot(String fileRoot) {
		this.fileRoot = fileRoot;
	}

	public String getCleanedUrlPath() {
		if (cleanedUrlPath == null) {
			cleanedUrlPath = cleanUrlPath(rawUrlPath);
		}
		
		return cleanedUrlPath;
	}
	
	public static String cleanUrlPath(String rawUrlPath) {
		if (rawUrlPath == null) {
			return null;
		} else {
			return rawUrlPath.replaceAll("/\\*/", "/{id}/").replaceAll("\\{[^\\}]+\\}", "{id}");
		}
	}
	
	public boolean matchesLineNumber(int lineNumber) {
		return lineNumber < endLineNumber && lineNumber > startLineNumber;
	}
	
	@Override
	public String toString() {
		return "[" + getCleanedFilePath() + 
				":" + startLineNumber + 
				"-" + endLineNumber + 
				" -> " + getCleanedUrlPath() + 
				"]"; 
	}
}
