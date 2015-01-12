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
package com.denimgroup.threadfix.plugins.intellij.markers;

import com.denimgroup.threadfix.data.entities.VulnerabilityMarker;
import com.denimgroup.threadfix.plugins.intellij.properties.Constants;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.editor.markup.GutterIconRenderer;
import com.intellij.openapi.util.IconLoader;
import javax.annotation.Nonnull;

import javax.swing.*;
import java.util.Set;
import java.util.TreeSet;

/**
 */
class ThreadFixMarkerRenderer extends GutterIconRenderer {

    private final Set<String> descriptions = new TreeSet<String>();
    private final int lineNumber;

    String compiledText = null;

    public ThreadFixMarkerRenderer(@Nonnull VulnerabilityMarker marker){
        descriptions.add(getInfo(marker));
        lineNumber = MarkerUtils.getLineNumber(marker);
    }

    @Override
    public java.lang.String getTooltipText() {
        if (compiledText == null) {
            StringBuilder builder = new StringBuilder();

            if (descriptions.size() > 1) {
                builder.append(descriptions.size()).append(" Vulnerabilities:");
            } else {
                builder.append("1 Vulnerability:");
            }

            for (String description : descriptions) {
                builder.append('\n').append(description);
            }

            compiledText = builder.toString();
        }
        return compiledText;
    }

    public int getLineNumber() {
        return lineNumber;
    }

    public void addMarkerInfo(@Nonnull VulnerabilityMarker marker) {
        descriptions.add(getInfo(marker));
    }

    private static String getInfo(VulnerabilityMarker marker) {
        StringBuilder builder = new StringBuilder(marker.getGenericVulnName());

        if (marker.getParameter() != null) {
            builder.append(" on variable ").append(marker.getParameter());
        } else {
            builder.append(" on page");
        }

        if (marker.getDefectId() != null) {
            builder.append(" (Defect ID ").append(marker.getDefectId()).append(")");
        }

        return builder.toString();
    }

    // TODO change to a transparent png
    @Nonnull
    @Override
    public Icon getIcon() {
        return IconLoader.getIcon(Constants.THREADFIX_ICON_NAME);
    }

    @Override
    public boolean equals(Object o) {
        return false;
    }

    @Override
    public int hashCode() {
        return 0;
    }

}
