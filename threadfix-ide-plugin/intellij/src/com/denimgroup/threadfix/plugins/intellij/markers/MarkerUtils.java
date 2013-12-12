package com.denimgroup.threadfix.plugins.intellij.markers;

import com.denimgroup.threadfix.plugins.intellij.rest.VulnerabilityMarker;
import com.denimgroup.threadfix.plugins.intellij.toolwindow.ThreadFixWindowFactory;
import com.denimgroup.threadfix.plugins.intellij.toolwindow.VulnerabilitiesTableModel;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.PlatformDataKeys;
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
import com.intellij.openapi.util.Key;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.ui.JBColor;
import org.jetbrains.annotations.NotNull;

import java.awt.*;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

/**
 * Created with IntelliJ IDEA.
 * User: mac
 * Date: 12/4/13
 * Time: 9:49 AM
 * To change this template use File | Settings | File Templates.
 */
public class MarkerUtils {

    public static final Key<VulnerabilityMarker> KEY = Key.create("com.denimgroup.threadfix.VulnerabilityMarker");

    private MarkerUtils(){}

    public static void createMarkers(Collection<VulnerabilityMarker> markers, AnActionEvent event) {
        Project project = event.getData(PlatformDataKeys.PROJECT);

        Map<String, Set<VirtualFile>> map = WorkspaceUtils.getAllFilesAsMap(project);

        for (Set<VirtualFile> fileSet : map.values()) {
            removeAll(fileSet, project);
        }

        VulnerabilitiesTableModel tableModel = ThreadFixWindowFactory.getTableModel();
        tableModel.clear();
        tableModel.initVirtualFiles(markers.size());
        tableModel.setProject(project);

        for (VulnerabilityMarker marker : markers) {

            if (map.containsKey(marker.getShortClassName())) {
                MarkupModel model = getMarkupModel(map, marker.getShortClassName(), project);

                addRenderers(marker, model);

                // TODO clean up
                tableModel.setVirtualFileAt(tableModel.getRowCount(),
                        map.get(marker.getShortClassName()).iterator().next());
                tableModel.addRow(marker.toStringArray());
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

    private static void addRenderers(@NotNull VulnerabilityMarker marker, @NotNull MarkupModel documentMarkupModel) {

        TextAttributes attributes = new TextAttributes();

        Color color = getHighlighterColor();

        attributes.setBackgroundColor(color);

        RangeHighlighter newHighlighter = documentMarkupModel.addLineHighlighter(marker.lineNumber, 500, attributes);

        boolean newLine = true;

        for (RangeHighlighter highlighter : documentMarkupModel.getAllHighlighters()) {
            if (highlighter.getGutterIconRenderer() instanceof ThreadFixMarkerRenderer) {
                ThreadFixMarkerRenderer renderer = ((ThreadFixMarkerRenderer) highlighter.getGutterIconRenderer());
                if (renderer != null && marker.lineNumber == renderer.getLineNumber()) {
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

}
