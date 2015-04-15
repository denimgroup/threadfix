////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
package com.denimgroup.threadfix.selenium.tests;

import com.denimgroup.threadfix.CommunityTests;
import com.denimgroup.threadfix.selenium.pages.*;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.openqa.selenium.By;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@Category(CommunityTests.class)
public class TagIndexPageIT extends BaseDataTest{

    @Test
    public void testCreateTag() {
        String tagName = getName();

        TagIndexPage tagIndexPage = loginPage.defaultLogin()
                .clickTagsLink()
                .createNewTag(tagName);

        assertTrue("Tag was not created properly", tagIndexPage.isTagNameLinkPresent(tagName));
    }

    @Test
    public void testDeleteTag() {
        String tagName = createTag();

        TagIndexPage tagIndexPage = loginPage.defaultLogin()
                .clickTagsLink()
                .deleteTag(tagName);

        assertTrue("Tag was not deleted properly", !tagIndexPage.isTagNameLinkPresent(tagName));
    }

    @Test
    public void testEditTag() {
        String tagName = createTag();
        String newName = getName();

        TagIndexPage tagIndexPage = loginPage.defaultLogin()
                .clickTagsLink()
                .editTagName(tagName,newName);

        assertTrue("Old tag name was not deleted properly", !tagIndexPage.isTagNameLinkPresent(tagName));
        assertTrue("New tag name was no added properly ", tagIndexPage.isTagNameLinkPresent(newName));
    }

    @Test
    public void testTagNameNavigation() {
        String tagName = createTag();

        loginPage.defaultLogin()
                .clickTagsLink()
                .clickTagName(tagName);

        assertTrue("Tag name did not navigate correctly",
                driver.findElement(By.linkText("Back to Tags Page")).isEnabled());
    }
}
