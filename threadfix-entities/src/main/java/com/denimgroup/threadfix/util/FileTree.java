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