package com.denimgroup.threadfix.service.merge;

public enum SourceCodeAccessLevel {
	NONE("None"), DETECT("Detect"), PARTIAL("Partial"), FULL("Full");
	
	SourceCodeAccessLevel(String displayName) {
		this.displayName = displayName;
	}
	
	String displayName;
	public String getDisplayName() { return displayName; }
	
	public static SourceCodeAccessLevel getSourceCodeAccessLevel(String input) {
		SourceCodeAccessLevel returnAccessLevel = DETECT; // default access level
		
		if (input != null) {
			for (SourceCodeAccessLevel sourceCodeAccessLevel : values()) {
				if (sourceCodeAccessLevel.toString().equals(input)) {
					returnAccessLevel = sourceCodeAccessLevel;
					break;
				}
			}
		}
		
		return returnAccessLevel;
	}
}