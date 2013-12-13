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
