////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
package com.denimgroup.threadfix.plugin.scanner.service.channel;

public enum ScanImportStatus {
	SUCCESSFUL_SCAN("Valid Scan file."),
	OLD_SCAN_ERROR("A newer scan from this scanner has been uploaded."),
	EMPTY_SCAN_ERROR("Scan file is empty."),
	DUPLICATE_ERROR("Scan file has already been uploaded."),
	WRONG_FORMAT_ERROR("Scan file is in the wrong format."),
	NULL_INPUT_ERROR("The scan could not be completed because there was null input"),
	OTHER_ERROR("The scan file encountered an unknown error."),
	BADLY_FORMED_XML("The XML was not well-formed and could not be parsed."),
	MORE_RECENT_SCAN_ON_QUEUE("There was a more recent scan for this application and scanner on the queue."),
	FAILED_XSD("The XML document did not pass the check against its XSD. Please edit it, check against the XSD, and try again.");
	
	ScanImportStatus(String messageText) {
		this.stringValue = messageText;
	}
	
	private final String stringValue;
	
	@Override
	public String toString() {
		return stringValue;
	}
}
