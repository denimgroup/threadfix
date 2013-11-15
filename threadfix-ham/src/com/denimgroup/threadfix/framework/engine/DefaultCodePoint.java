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
package com.denimgroup.threadfix.framework.engine;


public class DefaultCodePoint implements CodePoint {
	
	private final String lineText, sourceFileName;
	private final int lineNumber;
	
	public DefaultCodePoint(String sourceFileName, int lineNumber, String lineText) {
		this.lineText = lineText;
		this.sourceFileName = sourceFileName;
		this.lineNumber = lineNumber;
	}

	@Override
	public String getLineText() {
		return lineText;
	}

	@Override
	public int getLineNumber() {
		return lineNumber;
	}

	@Override
	public String getSourceFileName() {
		return sourceFileName;
	}

	
	
}
