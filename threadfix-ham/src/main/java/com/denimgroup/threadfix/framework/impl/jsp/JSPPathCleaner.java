package com.denimgroup.threadfix.framework.impl.jsp;

import com.denimgroup.threadfix.framework.engine.cleaner.DefaultPathCleaner;
import com.denimgroup.threadfix.framework.engine.partial.PartialMapping;
import com.denimgroup.threadfix.framework.util.CommonPathFinder;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.List;

public class JSPPathCleaner extends DefaultPathCleaner {

    public JSPPathCleaner(List<PartialMapping> partialMappings) {
        super(CommonPathFinder.findOrParseProjectRoot(partialMappings, ".jsp"),
                CommonPathFinder.findOrParseUrlPath(partialMappings, ".jsp"));
    }

    public JSPPathCleaner(String staticRoot, String dynamicRoot) {
        super(staticRoot, dynamicRoot);
    }

    @Nullable
    @Override
    public String getDynamicPathFromStaticPath(@NotNull String filePath) {
        String cleanedPath = filePath;

        if (staticRoot != null) {
            if (cleanedPath.contains("\\")) {
                cleanedPath = cleanedPath.replace('\\', '/');
            }

            String localRoot = staticRoot;

            if (!cleanedPath.startsWith(localRoot) &&
                    cleanedPath.indexOf("/") != 0) {
                cleanedPath = "/" + cleanedPath;
            }

            if (!cleanedPath.startsWith(localRoot) &&
                    localRoot.indexOf("/") != 0) {
                localRoot = "/" + localRoot;
            }

            if (cleanedPath.startsWith(localRoot)) {
                cleanedPath = cleanedPath.substring(localRoot.length());
            }
        }

        return cleanedPath;
    }

    @Override
    public String cleanDynamicPath(@NotNull String urlPath) {
        String cleanedPath = urlPath;

        if (cleanedPath.contains("\\")) {
            cleanedPath = cleanedPath.replace('\\', '/');
        }

        if (dynamicRoot != null && cleanedPath.startsWith(dynamicRoot)) {
            cleanedPath = cleanedPath.substring(dynamicRoot.length());
        }

        if (cleanedPath.indexOf("/") != 0) {
            cleanedPath = "/" + cleanedPath;
        }

        return cleanedPath;
    }

    @NotNull
    @Override
    public String toString() {
        return "[JSP PathCleaner dynamicRoot = " +
                dynamicRoot + ", staticRoot = " + staticRoot + "]";
    }

}
