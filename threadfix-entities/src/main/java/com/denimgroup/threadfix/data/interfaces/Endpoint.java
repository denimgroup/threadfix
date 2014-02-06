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
package com.denimgroup.threadfix.data.interfaces;

import org.jetbrains.annotations.NotNull;

import java.util.Set;

public interface Endpoint extends Comparable<Endpoint> {

    @NotNull
	Set<String> getParameters();

    @NotNull
	Set<String> getHttpMethods();

    @NotNull
	String getUrlPath();

    @NotNull
	String getFilePath();

    @NotNull
	String getCSVLine();
	
	int getStartingLineNumber();
	
	int getLineNumberForParameter(String parameter);
	
	boolean matchesLineNumber(int lineNumber);

    public static class Info {
        Set<String> parameters, httpMethods;

        String urlPath, filePath, csvLine;

        int startingLineNumber;

        public static Info fromEndpoint(Endpoint endpoint) {
            Info info = new Info();
            info.parameters = endpoint.getParameters();
            info.httpMethods = endpoint.getHttpMethods();
            info.urlPath = endpoint.getUrlPath();
            info.filePath = endpoint.getFilePath();
            info.csvLine = endpoint.getCSVLine();
            info.startingLineNumber = endpoint.getStartingLineNumber();
            return info;
        }

        public Set<String> getParameters() {
            return parameters;
        }

        public Set<String> getHttpMethods() {
            return httpMethods;
        }

        public String getUrlPath() {
            return urlPath;
        }

        public String getFilePath() {
            return filePath;
        }

        public String getCsvLine() {
            return csvLine;
        }

        public int getStartingLineNumber() {
            return startingLineNumber;
        }
    }
	
}
