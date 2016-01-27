////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

package com.denimgroup.threadfix.plugins.intellij.action;

import com.denimgroup.threadfix.data.entities.VulnerabilityMarker;
import com.denimgroup.threadfix.plugins.intellij.markers.MarkerUtils;
import com.denimgroup.threadfix.plugins.intellij.rest.VulnerabilityMarkerService;
import com.intellij.openapi.fileEditor.FileEditorManager;
import com.intellij.openapi.fileEditor.FileEditorManagerEvent;
import com.intellij.openapi.fileEditor.FileEditorManagerListener;
import com.intellij.openapi.module.ModuleComponent;
import com.intellij.openapi.module.Module;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.util.messages.MessageBusConnection;
import javax.annotation.Nonnull;

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
            public void fileOpened(@Nonnull FileEditorManager source, @Nonnull VirtualFile file) {
                List<VulnerabilityMarker> markers = VulnerabilityMarkerService.getMarkersCache();

                if (!hasBuiltTable) {
                    MarkerUtils.createMarkers(markers, finalProject);
                    hasBuiltTable = true;
                }

                MarkerUtils.addMarkersToFile(finalProject, file, markers);
            }

            @Override
            public void fileClosed(@Nonnull FileEditorManager source, @Nonnull VirtualFile file) {
            }

            @Override
            public void selectionChanged(@Nonnull FileEditorManagerEvent event) {
            }
        };
    }

    public void initComponent() {
        // TODO: insert component initialization logic here
    }

    public void disposeComponent() {
        // TODO: insert component disposal logic here
    }

    @Nonnull
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
