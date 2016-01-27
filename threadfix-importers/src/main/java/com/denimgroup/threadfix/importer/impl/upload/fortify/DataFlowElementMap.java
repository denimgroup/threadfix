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
package com.denimgroup.threadfix.importer.impl.upload.fortify;

/**
 * Created by mcollins on 2/16/15.
 */
class DataFlowElementMap {

    String line = null, column = null, lineText = null, fileName = null,
            node = null, snippet = null, fact = null, action = null, taint;

    public void merge(DataFlowElementMap other) {
        if (line == null && other.line != null)
            this.line = other.line;
        if (lineText == null && other.lineText != null)
            this.lineText = other.lineText;
        if (column == null && other.column != null)
            this.column = other.column;
        if (fileName == null && other.fileName != null)
            this.fileName = other.fileName;
        if (node == null && other.node != null)
            this.node = other.node;
        if (snippet == null && other.snippet != null)
            this.snippet = other.snippet;
        if (fact == null && other.fact != null)
            this.fact = other.fact;
        if (action == null && other.action != null)
            this.action = other.action;

    }
}
