package com.denimgroup.threadfix.framework.engine.framework;

import com.denimgroup.threadfix.framework.engine.ProjectDirectory;
import com.denimgroup.threadfix.framework.enums.FrameworkType;
import com.denimgroup.threadfix.framework.filefilter.FileExtensionFileFilter;
import com.denimgroup.threadfix.framework.impl.spring.SpringJavaConfigurationChecker;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.jetbrains.annotations.NotNull;

import java.io.File;
import java.util.Collection;

/**
 * Created by mac on 1/7/14.
 */
public class SpringJavaFrameworkChecker extends FrameworkChecker {

    @NotNull
    @Override
    @SuppressWarnings("unchecked")
    public FrameworkType check(@NotNull ProjectDirectory directory) {
        Collection<File> files = FileUtils.listFiles(directory.getDirectory(),
                new FileExtensionFileFilter("java"), TrueFileFilter.INSTANCE);

        FrameworkType type = FrameworkType.NONE;

        for (File file : files) {
            if (SpringJavaConfigurationChecker.checkJavaFile(file)) {
                type = FrameworkType.SPRING_MVC;
                break;
            }
        }

        return type;
    }
}
