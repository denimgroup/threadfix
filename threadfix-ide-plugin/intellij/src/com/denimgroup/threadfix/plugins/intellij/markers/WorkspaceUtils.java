package com.denimgroup.threadfix.plugins.intellij.markers;

import com.intellij.openapi.editor.Document;
import com.intellij.openapi.editor.Editor;
import com.intellij.openapi.editor.EditorFactory;
import com.intellij.openapi.fileEditor.FileEditorManager;
import com.intellij.openapi.fileEditor.FileEditorProvider;
import com.intellij.openapi.fileEditor.OpenFileDescriptor;
import com.intellij.openapi.fileEditor.impl.text.TextEditorProvider;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vcs.vfs.VcsFileSystem;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.openapi.vfs.VirtualFileManager;
import com.intellij.openapi.vfs.VirtualFileSystem;
import com.intellij.psi.PsiDocumentManager;
import com.intellij.psi.PsiFile;
import com.intellij.psi.PsiManager;
import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.util.*;

/**
 * Created with IntelliJ IDEA.
 * User: mac
 * Date: 12/4/13
 * Time: 2:53 PM
 * To change this template use File | Settings | File Templates.
 */
public class WorkspaceUtils {

    private WorkspaceUtils(){}

    public static void openFile(Project project, VirtualFile file, int lineNumber) {

        if (file.isValid()) {
            FileEditorManager.getInstance(project).openTextEditor(new OpenFileDescriptor(project, file, lineNumber), true);
        } else {
            System.out.println("Weird, VirtualFile.isValid() returned false.");
        }

        // TODO file.
    }

    public static Map<String, Set<VirtualFile>> getAllFilesAsMap(Project project) {
        Map<String, Set<VirtualFile>> map = new HashMap<String, Set<VirtualFile>>();

        if (project != null && project.getProjectFile() != null && project.getBaseDir().exists()) {

            MapEntryCollector entryCollector = new MapEntryCollector();
            visitChildrenRecursively(project.getBaseDir(), entryCollector);
            map = entryCollector.fileMap;
        }

        return map;
    }

    public static Collection<VirtualFile> getAllFilesAsCollection(Project project) {
        Collection<VirtualFile> map = new ArrayList<VirtualFile>();

        if (project != null && project.getProjectFile() != null && project.getBaseDir().exists()) {

            CollectionCollector entryCollector = new CollectionCollector();
            visitChildrenRecursively(project.getBaseDir(), entryCollector);
            map = entryCollector.fileCollection;
        }

        return map;
    }

    private static void visitChildrenRecursively(@NotNull VirtualFile file, Collector collector) {

        // IntelliJ warns about file.getChildren because of symlinks, but we check for symlinks.
        // This is the same protection afforded by their proposed VfsUtilCore solution.
        if (file.isDirectory() && !file.getName().startsWith(".") &&
                !file.isSymLink() && file.getChildren() != null) {
            for (VirtualFile childFile : file.getChildren()) {
                visitChildrenRecursively(childFile, collector);
            }
        } else if (!file.isDirectory()) {
            collector.collect(file);
        }
    }

    interface Collector {
        void collect(@NotNull VirtualFile file);
    }

    private static class MapEntryCollector implements Collector {

        private final Map<String, Set<VirtualFile>> fileMap = new HashMap<String, Set<VirtualFile>>();

        public void collect(@NotNull VirtualFile file) {
            if (!fileMap.containsKey(file.getName())) {
                fileMap.put(file.getName(), new HashSet<VirtualFile>());
            }

            fileMap.get(file.getName()).add(file);
        }
    }

    private static class CollectionCollector implements Collector {
        private final Collection<VirtualFile> fileCollection = new ArrayList<VirtualFile>();

        public void collect(@NotNull VirtualFile file) {
            fileCollection.add(file);
        }
    }

}
