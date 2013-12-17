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
package com.denimgroup.threadfix.plugins.intellij.markers;

import com.denimgroup.threadfix.plugins.intellij.properties.Constants;
import com.denimgroup.threadfix.plugins.intellij.rest.VulnerabilityMarker;
import com.intellij.openapi.editor.markup.GutterIconRenderer;
import com.intellij.openapi.util.IconLoader;
import org.jetbrains.annotations.NotNull;

import javax.swing.*;

/**
 * Created with IntelliJ IDEA.
 * User: mac
 * TODO flesh out and add real icon
 */
class ThreadFixMarkerRenderer extends GutterIconRenderer {

    private final StringBuilder text;
    private final int lineNumber;

    public ThreadFixMarkerRenderer(VulnerabilityMarker marker){
        text = new StringBuilder(marker.toString());
        lineNumber = marker.lineNumber;
    }

    @Override
    public java.lang.String getTooltipText() {
        return text.toString();
    }

    public int getLineNumber() {
        return lineNumber;
    }

    public void addMarkerInfo(@NotNull VulnerabilityMarker marker) {
        text.append('\n').append(marker.toString());
    }

    // TODO change to a transparent png
    @NotNull
    @Override
    public Icon getIcon() {

        Icon icon = IconLoader.getIcon(Constants.THREADFIX_ICON_NAME);

        return icon;
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
