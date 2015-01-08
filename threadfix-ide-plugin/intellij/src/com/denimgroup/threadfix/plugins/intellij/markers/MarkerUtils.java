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
import com.denimgroup.threadfix.plugins.intellij.toolwindow.ThreadFixWindowFactory;
import com.denimgroup.threadfix.plugins.intellij.toolwindow.VulnerabilitiesTableModel;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.PlatformDataKeys;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.editor.colors.EditorColors;
import com.intellij.openapi.editor.colors.EditorColorsManager;
import com.intellij.openapi.editor.colors.EditorColorsScheme;
import com.intellij.openapi.editor.impl.DocumentMarkupModel;
import com.intellij.openapi.editor.markup.GutterIconRenderer;
import com.intellij.openapi.editor.markup.MarkupModel;
import com.intellij.openapi.editor.markup.RangeHighlighter;
import com.intellij.openapi.editor.markup.TextAttributes;
import com.intellij.openapi.fileEditor.FileDocumentManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.ui.JBColor;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import java.awt.*;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

public class MarkerUtils {

    private MarkerUtils(){}

    private static final Logger log = Logger.getInstance(MarkerUtils.class);

    public static void createMarkers(Collection<VulnerabilityMarker> markers, Project project) {
        createMarkers(markers, project, true);
    }

    public static void createMarkers(Collection<VulnerabilityMarker> markers, Project project, boolean addRenderer) {
        Map<String, Set<VirtualFile>> map = WorkspaceUtils.getAllFilesAsMap(project);

        for (Set<VirtualFile> fileSet : map.values()) {
            removeAll(fileSet, project);
        }

        VulnerabilitiesTableModel tableModel = ThreadFixWindowFactory.getTableModel();
        tableModel.clear();
        tableModel.initVirtualFiles(markers.size());
        tableModel.setProject(project);

        for (VulnerabilityMarker marker : markers) {

            String shortClassName = getShortClassName(marker);

            if (map.containsKey(shortClassName)) {

                if (addRenderer) {
                    MarkupModel model = getMarkupModel(map, shortClassName, project);
                    addRenderers(marker, model);
                }

                // TODO clean up
                tableModel.setVirtualFileAt(tableModel.getRowCount(),
                        map.get(shortClassName).iterator().next());
                tableModel.addRow(toStringArray(marker));
            } else {
                log.info("Failed to attach marker to class " + shortClassName + ", full path was " + marker.getFilePath());
            }
        }
    }

    public static String[] getHeaders() {
        return new String[] { "Resource", "Line Number", "Parameter", "CWE ID", "CWE Name (double click to open)", "Defect URL (double click to open)" };
    }

    public static final int
            LINE_NUMBER_INDEX = 1,
            CWE_ID_INDEX = 3,
            CWE_TEXT_INDEX = 4,
            DEFECT_URL_INDEX = 5;

    public static String[] toStringArray(VulnerabilityMarker marker) {
        String lineNumber = marker.getLineNumber();

        if (lineNumber != null && lineNumber.trim().equals("0")) {
            lineNumber = "";
        }

        return new String[] {marker.getFilePath(),
                lineNumber,
                marker.getParameter(),
                marker.getGenericVulnId(),
                marker.getGenericVulnName(),
                marker.getDefectUrl() };
    }

    @Nullable
    public static String getShortClassName(VulnerabilityMarker marker) {

        String[] classNameParts = null;

        if (marker != null && marker.getFilePath() != null) {
            classNameParts = marker.getFilePath().split("/");
        }

        if (classNameParts != null && classNameParts.length > 0) {
            return classNameParts[classNameParts.length - 1];
        } else {
            return null;
        }
    }

    public static void addMarkersToFile(Project project, VirtualFile file,
                                        Iterable<VulnerabilityMarker> markers) {
        MarkupModel model = getMarkupModel(file, project, true);

        for (VulnerabilityMarker marker : markers) {
            String shortClassName = getShortClassName(marker);
            if (shortClassName != null && shortClassName.equals(file.getName())) {
                addRenderers(marker, model);
            }
        }
    }

    public static void removeMarkers(AnActionEvent event) {
        Project project = event.getData(PlatformDataKeys.PROJECT);

        Collection<VirtualFile> fileSet = WorkspaceUtils.getAllFilesAsCollection(project);

        removeAll(fileSet, project);
    }

    private static void removeAll(Collection<VirtualFile> files, Project project) {
        for (VirtualFile virtualFile : files) {
            MarkupModel model = getMarkupModel(virtualFile, project, false);

            if (model != null) {
                removeThreadFixRenderers(model);
            }
        }
    }

    private static MarkupModel getMarkupModel(Map<String, Set<VirtualFile>> map, String shortClassName,
                                              Project project) {
        return getMarkupModel(map.get(shortClassName).iterator().next(), project, true);
    }

    private static MarkupModel getMarkupModel(VirtualFile virtualFile, Project project, boolean create) {
        MarkupModel returnModel = null;

        Document document = FileDocumentManager.getInstance().getDocument(virtualFile);

        if (document != null) {
            returnModel = DocumentMarkupModel.forDocument(document, project, create);
        }

        return returnModel;
    }

    private static Color getHighlighterColor() {
        EditorColorsManager manager = EditorColorsManager.getInstance();
        if (manager != null) {
            EditorColorsScheme globalScheme = manager.getGlobalScheme();

            return globalScheme.getColor(EditorColors.SELECTION_FOREGROUND_COLOR);
        } else {
            return JBColor.getHSBColor(.0f, .37f, .99f);
        }
    }

    private static void addRenderers(@Nonnull VulnerabilityMarker marker, @Nonnull MarkupModel documentMarkupModel) {

        TextAttributes attributes = new TextAttributes();

        Color color = getHighlighterColor();

        attributes.setBackgroundColor(color);

        int markerLineNumber = getLineNumber(marker);

        RangeHighlighter newHighlighter = documentMarkupModel.addLineHighlighter(markerLineNumber, 500, attributes);

        boolean newLine = true;

        for (RangeHighlighter highlighter : documentMarkupModel.getAllHighlighters()) {
            if (highlighter.getGutterIconRenderer() instanceof ThreadFixMarkerRenderer) {
                ThreadFixMarkerRenderer renderer = ((ThreadFixMarkerRenderer) highlighter.getGutterIconRenderer());
                if (renderer != null && markerLineNumber == renderer.getLineNumber()) {
                    newLine = false;
                    renderer.addMarkerInfo(marker);
                    break;
                }
            }
        }

        if (newLine) {
            newHighlighter.setGutterIconRenderer(new ThreadFixMarkerRenderer(marker));
        }
    }

    private static void removeThreadFixRenderers(MarkupModel markupModel)
    {
        RangeHighlighter[] allHighlighters = markupModel.getAllHighlighters();

        for (RangeHighlighter highlighter : allHighlighters)
        {
            GutterIconRenderer gutterIconRenderer = highlighter.getGutterIconRenderer();
            if (gutterIconRenderer instanceof ThreadFixMarkerRenderer)
            {
                markupModel.removeHighlighter(highlighter);
            }
        }
    }

    public static Integer getLineNumber(@Nonnull VulnerabilityMarker marker) {
        if (marker.getLineNumber() != null && marker.getLineNumber().matches("^[0-9]+$")) {
            Integer integer = Integer.valueOf(marker.getLineNumber());
            return integer == 0 ? 0 : integer - 1; // somehow this got off by one.
        } else {
            return 0;
        }
    }


}
