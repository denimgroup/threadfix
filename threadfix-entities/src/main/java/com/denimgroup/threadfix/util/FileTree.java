package com.denimgroup.threadfix.util;


import java.io.File;
import java.util.List;
import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 *
 * @author zabdisubhan
 */

public class FileTree {

    List<String> resultFilePaths;

    public List<String> getResultFilePaths() {
        return resultFilePaths;
    }

    public void setResultFilePaths(List<String> resultFilePaths) {
        this.resultFilePaths = resultFilePaths;
    }

    public void walk(File root) {

        if (!root.isDirectory())
            return;

        File[] list = root.listFiles();

        if (list == null) return;

        for ( File f : list ) {
            if ( f.isDirectory() ) {
                walk( f.getAbsoluteFile() );
            } else {
                List<String> filePaths = getResultFilePaths();
                if (filePaths == null) {
                    filePaths = list();
                }
                filePaths.add(f.getAbsolutePath());
                setResultFilePaths(filePaths);
            }
        }
    }
}