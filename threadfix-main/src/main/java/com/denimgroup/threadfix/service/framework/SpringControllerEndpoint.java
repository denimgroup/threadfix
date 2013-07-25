package com.denimgroup.threadfix.service.framework;

public class SpringControllerEndpoint {
	
	public static final String GENERIC_INT_SEGMENT = "{id}";

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
			cleanedUrlPath = cleanUrlPathStatic(rawUrlPath);
		}
		
		return cleanedUrlPath;
	}
	
	public static String cleanUrlPathStatic(String rawUrlPath) {
		if (rawUrlPath == null) {
			return null;
		} else {
			return rawUrlPath
					.replaceAll("/\\*/", "/" + GENERIC_INT_SEGMENT + "/")
					.replaceAll("\\{[^\\}]+\\}", GENERIC_INT_SEGMENT);
		}
	}
	
	public static String cleanUrlPathDynamic(String rawUrlPath) {
		if (rawUrlPath == null) {
			return null;
		} else {
			return rawUrlPath.replaceAll("/[0-9]+/", "/" + GENERIC_INT_SEGMENT + "/").replaceAll("\\.html", "");
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
