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
package com.denimgroup.threadfix.framework.util;

/**
 * This class eases token processing using streams. It's meant to be used with 
 * {@link EventBasedTokenizerRunner} which has methods to process a file using an
 * implementation of this class. It calls run for each token that the parser encounters.
 * 
 * @author mcollins
 */
public interface EventBasedTokenizer {
	
	static Character 
		ARROBA = '@',
		EQUALS = '=', 
		COMMA = ',', 
		DOUBLE_QUOTE = '"',
		COLON = ':',
		SEMICOLON = ';',
		PERCENT = '%',
		OPEN_ANGLE_BRACKET = '<',
		CLOSE_ANGLE_BACKET = '>',
		OPEN_PAREN = '(',
		CLOSE_PAREN = ')',
		OPEN_CURLY = '{',
		CLOSE_CURLY = '}';
	
	void processToken(int type, int lineNumber, String stringValue);

}
