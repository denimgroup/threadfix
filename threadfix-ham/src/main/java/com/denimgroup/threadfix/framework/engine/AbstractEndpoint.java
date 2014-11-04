////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.interfaces.Endpoint;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;


public abstract class AbstractEndpoint implements Endpoint {
	
	@Override
	public int compareTo(@Nullable Endpoint otherEndpoint) {
		int returnValue = 0;
		
		if (otherEndpoint != null) {
			
            returnValue -= 2 * otherEndpoint.getFilePath().compareTo(getFilePath());

			if (getStartingLineNumber() < otherEndpoint.getStartingLineNumber()) {
				returnValue -= 1;
			} else {
				returnValue += 1;
			}
		}
		
		return returnValue;
	}
	
	// TODO finalize this
	@Nonnull
    @Override
	public String getCSVLine(PrintFormat... formats) {
        Set<PrintFormat> formatSet = new HashSet<>(Arrays.asList(formats));

        StringBuilder builder = new StringBuilder();

        if (formatSet.contains(PrintFormat.LINT)) {
            List<String> lintLines = getLintLine();

            if (!lintLines.isEmpty()) {
                String staticInformation = getStaticCSVFields();

                for (String lintLine : lintLines) {
                    builder.append(staticInformation).append(",").append(lintLine).append("\n");
                }

                builder.deleteCharAt(builder.length() - 1);
            } else {
                return getCSVLine(PrintFormat.DYNAMIC);
            }
        }

        if (formatSet.contains(PrintFormat.STATIC) && formatSet.contains(PrintFormat.DYNAMIC)) {
            builder.append(getStaticCSVFields()).append(',').append(getDynamicCSVFields());
        } else if (formatSet.contains(PrintFormat.STATIC)) {
            builder.append(getStaticCSVFields());
        } else if (!formatSet.contains(PrintFormat.LINT)) {
		    builder.append(getDynamicCSVFields());
        }

        return builder.toString();
	}

    @Nonnull
    protected abstract List<String> getLintLine();

    protected String getDynamicCSVFields() {
        String parameters = getToStringNoCommas(getParameters());

        if (parameters.length() > 200) {
            parameters = parameters.substring(0, 200) + "...";
        }

        return getToStringNoCommas(getHttpMethods()) + "," +
                getUrlPath() + "," +
                parameters;
    }

    protected String getStaticCSVFields() {
        return getFilePath() + "," + getStartingLineNumber();
    }
	
	private String getToStringNoCommas(@Nonnull Object object) {
        return object.toString().replaceAll(",", "");
	}
	
	@Nonnull
    @Override
	public String toString() {
		return getCSVLine();
	}

}
