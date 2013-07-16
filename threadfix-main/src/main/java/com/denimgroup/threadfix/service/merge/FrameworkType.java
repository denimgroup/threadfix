package com.denimgroup.threadfix.service.merge;

public enum FrameworkType {
	NONE("None"), DETECT("Detect"), JSP("JSP"), SPRING_MVC("Spring MVC");
	
	FrameworkType(String displayName) {
		this.displayName = displayName;
	}
	
	String displayName;
	public String getDisplayName() { return displayName; }
	
	public static FrameworkType getFrameworkType(String input) {
		FrameworkType type = DETECT; // default framework type
		
		if (input != null) {
			for (FrameworkType frameworkType : values()) {
				if (frameworkType.toString().equals(input)) {
					type = frameworkType;
					break;
				}
			}
		}
		
		return type;
	}
}