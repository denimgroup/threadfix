package com.denimgroup.threadfix.plugins.intellij.action;

import com.denimgroup.threadfix.plugins.intellij.markers.MarkerUtils;
import com.denimgroup.threadfix.plugins.intellij.rest.VulnerabilityMarker;
import com.denimgroup.threadfix.plugins.intellij.rest.VulnerabilityMarkerService;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.fileEditor.FileEditorManager;
import com.intellij.openapi.fileEditor.FileEditorManagerEvent;
import com.intellij.openapi.fileEditor.FileEditorManagerListener;
import com.intellij.openapi.module.ModuleComponent;
import com.intellij.openapi.module.Module;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.util.messages.MessageBusConnection;
import org.jetbrains.annotations.NotNull;

import java.util.List;

/**
 * Created by mac on 12/13/13.
 */
public class TestModuleComponent implements ModuleComponent {
    public TestModuleComponent(Module module) {
        final Project finalProject = module.getProject();
        MessageBusConnection myConnection = finalProject.getMessageBus().connect(finalProject);
        myConnection.subscribe(FileEditorManagerListener.FILE_EDITOR_MANAGER, getListener(finalProject, myConnection));
    }

    private FileEditorManagerListener getListener(final Project finalProject, final MessageBusConnection myConnection) {
        return new FileEditorManagerListener() {

            boolean hasBuiltTable = false;

            @Override
            public void fileOpened(@NotNull FileEditorManager source, @NotNull VirtualFile file) {
                List<VulnerabilityMarker> markers = VulnerabilityMarkerService.getMarkersCache();

                if (!hasBuiltTable) {
                    MarkerUtils.createMarkers(markers, finalProject);
                    hasBuiltTable = true;
                }

                MarkerUtils.addMarkersToFile(finalProject, file, markers);
            }

            @Override
            public void fileClosed(@NotNull FileEditorManager source, @NotNull VirtualFile file) {
            }

            @Override
            public void selectionChanged(@NotNull FileEditorManagerEvent event) {
            }
        };
    }

    public void initComponent() {
        // TODO: insert component initialization logic here
    }

    public void disposeComponent() {
        // TODO: insert component disposal logic here
    }

    @NotNull
    public String getComponentName() {
        return "TestModuleComponent";
    }

    public void projectOpened() {
        // called when project is opened
    }

    public void projectClosed() {
        // called when project is being closed
    }

    public void moduleAdded() {
        // Invoked when the module corresponding to this component instance has been completely
        // loaded and added to the project.
    }
}
