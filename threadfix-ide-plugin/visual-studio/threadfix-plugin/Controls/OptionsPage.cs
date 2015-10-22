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
//     The Initial Developer of the Origin Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
using System.ComponentModel;
using Microsoft.VisualStudio.Shell;

namespace DenimGroup.threadfix_plugin.Controls
{
    public class OptionsPage : DialogPage
    {
        [Category("ThreadFix Settings")]
        [DisplayName("Api Key")]
        [Description("ThreadFix Api Key")]
        public string ApiKey { get; set; }

        [Category("ThreadFix Settings")]
        [DisplayName("Api Url")]
        [Description("ThreadFix Api Url")]
        public string ApiUrl { get; set; }
    }
}
