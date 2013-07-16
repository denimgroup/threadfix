package com.denimgroup.threadfix.service.merge;

public enum VulnTypeStrategy {
	EXACT("Exact"), TREES("Trees"), FAULT_PATTERN("Fault Pattern");
	
	VulnTypeStrategy(String displayName) {
		this.displayName = displayName;
	}
	
	String displayName;
	public String getDisplayName() { return displayName; }
	
	public static VulnTypeStrategy getVulnTypeStrategy(String input) {
		VulnTypeStrategy typeStrategy = EXACT; // default framework type
		
		if (input != null) {
			for (VulnTypeStrategy vulnTypeStrategy : values()) {
				if (vulnTypeStrategy.toString().equals(input)) {
					typeStrategy = vulnTypeStrategy;
					break;
				}
			}
		}
		
		return typeStrategy;
	}
}
