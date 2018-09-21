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

// Guids.cs
// MUST match guids.h
using System;

namespace DenimGroup.threadfix_plugin
{
    static class GuidList
    {
        public const string guidthreadfix_pluginPkgString = "b0aac42e-c9d3-45f8-bdf7-24d44347f3f9";
        public const string guidthreadfix_pluginCmdSetString = "24a6ce88-31e6-4395-afe9-716d6c06c1ac";

        public static readonly Guid guidthreadfix_pluginCmdSet = new Guid(guidthreadfix_pluginCmdSetString);
       
    };
}