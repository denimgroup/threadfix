////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
package com.denimgroup.threadfix.framework.impl.jsp;

import com.denimgroup.threadfix.framework.util.EventBasedTokenizer;
import com.denimgroup.threadfix.framework.util.EventBasedTokenizerRunner;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.File;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.set;

class JSPIncludeParser implements EventBasedTokenizer {
	
	@Nonnull
    private State currentState = State.START;
	@Nonnull
    Set<File> returnFiles = set();

    @Nonnull
    final File file;

	private enum State {
		START, JSP_INCLUDE, PAGE, EQUALS, OPEN_ANGLE, PERCENT, ARROBA, FILE
	}
	
	private static final Pattern slashPattern = Pattern.compile("[\\\\/]");

	JSPIncludeParser(@Nonnull File file) {
        this.file = file;
	}
	
	@Nonnull
    public static Set<File> parse(@Nonnull File file) {
		JSPIncludeParser parser = new JSPIncludeParser(file);
		EventBasedTokenizerRunner.run(file, false, parser);
		return parser.returnFiles;
	}

    @Override
    public boolean shouldContinue() {
        return true;
    }

    @Override
	public void processToken(int type, int lineNumber, @Nullable String stringValue) {
		switch (currentState) {
			case START:
				if (stringValue != null && stringValue.equals("jsp:include")) {
					currentState = State.JSP_INCLUDE;
				} else if (type == OPEN_ANGLE_BRACKET) {
					currentState = State.OPEN_ANGLE;
				}
				break;
			case JSP_INCLUDE:
				if (stringValue != null && stringValue.equals("page")) {
					currentState = State.PAGE;
				} else if (type == OPEN_ANGLE_BRACKET) {
					// if we hit another start tag let's head back to the start
					currentState = State.START;
				}
				break;
			case PAGE:
				if (type == EQUALS) {
					currentState = State.EQUALS;
				} else {
					currentState = State.START;
				}
				break;
			case EQUALS:
				if (type == DOUBLE_QUOTE && stringValue != null) {
					returnFiles.add(getRelativeFile(stringValue));
				}
				currentState = State.START;
				break;
			case OPEN_ANGLE:
				if (stringValue != null && stringValue.equals("jsp:include")) {
					currentState = State.JSP_INCLUDE;
				} else if (type == PERCENT) {
					currentState = State.PERCENT;
				} else {
					currentState = State.START;
				}
				break;
			case PERCENT:
				if (type == ARROBA) {
					currentState = State.ARROBA;
				} else {
					currentState = State.START;
				}
				break;
			case ARROBA:
				if (stringValue != null && stringValue.equals("file")) {
					currentState = State.PAGE;
				} else if (type == OPEN_ANGLE_BRACKET) {
					// if we hit another start tag let's head back to the start
					currentState = State.START;
				}
				break;
			case FILE:
				if (type == EQUALS) {
					currentState = State.EQUALS;
				} else {
					currentState = State.START;
				}
				break;
		}
	}

    @Nonnull
    private File getRelativeFile(String sval) {
        List<String>
                inputFilePathSegments = list(slashPattern.split(file.getParent())),
                svalPathSegments = list(slashPattern.split(sval));

        if (svalPathSegments.size() > 0) {
            for (String string : svalPathSegments) {
                if ("..".equals(string)) {
                    inputFilePathSegments.remove(inputFilePathSegments.size() - 1);
                } else if (string != null) {
                    inputFilePathSegments.add(string);
                }
            }
        }

        StringBuilder builder = new StringBuilder();
        for (String segment : inputFilePathSegments) {
            builder.append(segment);
            builder.append(File.separator);
        }

        String resultingString = builder.substring(0, builder.length() - 1);

        return new File(resultingString);
    }
}
