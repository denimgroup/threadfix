package com.denimgroup.threadfix.service.channel;

public enum ScanImportStatus {
	SUCCESSFUL_SCAN("Valid Scan file."),
	OLD_SCAN_ERROR("A newer scan from this scanner has been uploaded."),
	EMPTY_SCAN_ERROR("Scan file is empty."),
	DUPLICATE_ERROR("Scan file has already been uploaded."),
	WRONG_FORMAT_ERROR("Scan file is in the wrong format."),
	NULL_INPUT_ERROR("The scan could not be completed because there was null input"),
	OTHER_ERROR("The scan file encountered an unknown error."),
	BADLY_FORMED_XML("The XML was not well-formed and could not be parsed."),
	MORE_RECENT_SCAN_ON_QUEUE("There was a more recent scan for this application and scanner on the queue.");
	
	
	ScanImportStatus(String messageText) {
		this.stringValue = messageText;
	}
	
	private final String stringValue;
	
	public String toString() { 
		return stringValue;
	}
}
