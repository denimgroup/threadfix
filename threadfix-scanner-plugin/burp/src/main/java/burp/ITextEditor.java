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

package burp;

/*
 * @(#)ITextEditor.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

import java.awt.*;

/**
 * This interface is used to provide extensions with an instance of Burp's raw
 * text editor, for the extension to use in its own UI. Extensions should call
 * <code>IBurpExtenderCallbacks.createTextEditor()</code> to obtain an instance
 * of this interface.
 */
public interface ITextEditor
{
    /**
     * This method returns the UI component of the editor, for extensions to add
     * to their own UI.
     *
     * @return The UI component of the editor.
     */
    Component getComponent();

    /**
     * This method is used to control whether the editor is currently editable.
     * This status can be toggled on and off as required.
     *
     * @param editable Indicates whether the editor should be currently
     * editable.
     */
    void setEditable(boolean editable);

    /**
     * This method is used to update the currently displayed text in the editor.
     *
     * @param text The text to be displayed.
     */
    void setText(byte[] text);

    /**
     * This method is used to retrieve the currently displayed text.
     *
     * @return The currently displayed text.
     */
    byte[] getText();

    /**
     * This method is used to determine whether the user has modified the
     * contents of the editor.
     *
     * @return An indication of whether the user has modified the contents of
     * the editor since the last call to
     * <code>setText()</code>.
     */
    boolean isTextModified();

    /**
     * This method is used to obtain the currently selected text.
     *
     * @return The currently selected text, or
     * <code>null</code> if the user has not made any selection.
     */
    byte[] getSelectedText();

    /**
     * This method can be used to retrieve the bounds of the user's selection
     * into the displayed text, if applicable.
     *
     * @return An int[2] array containing the start and end offsets of the
     * user's selection within the displayed text. If the user has not made any
     * selection in the current message, both offsets indicate the position of
     * the caret within the editor.
     */
    int[] getSelectionBounds();

    /**
     * This method is used to update the search expression that is shown in the
     * search bar below the editor. The editor will automatically highlight any
     * regions of the displayed text that match the search expression.
     *
     * @param expression The search expression.
     */
    void setSearchExpression(String expression);
}
