package com.denimgroup.threadfix.service.framework;

public class SpringControllerEndpoint {

	private final String rawFilePath, rawUrlPath;
	private final int lineNumber;
	
	private String cleanedFilePath = null, cleanedUrlPath = null;
	
	private String fileRoot;
	
	public SpringControllerEndpoint(String filePath, String urlPath, int lineNumber) {
		this.rawFilePath = filePath;
		this.rawUrlPath = urlPath;
		this.lineNumber = lineNumber;
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
			cleanedUrlPath = rawUrlPath.replaceAll("/\\*/", "/{id}/").replaceAll("\\{[^\\}]+\\}", "{id}");
		}
		
		return cleanedUrlPath;
	}
	
	public int getLineNumber() {
		return lineNumber;
	}
	
	@Override
	public String toString() {
		return "[" + getCleanedFilePath() + ":" + lineNumber + " -> " + getCleanedUrlPath() + "]"; 
	}
}
