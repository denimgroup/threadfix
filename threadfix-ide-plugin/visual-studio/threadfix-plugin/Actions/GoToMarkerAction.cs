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
using DenimGroup.threadfix_plugin.Data;
using DenimGroup.threadfix_plugin.Utils;
using EnvDTE;
using EnvDTE80;
using Microsoft.VisualStudio.Shell;
using System;
using System.Diagnostics;

namespace DenimGroup.threadfix_plugin.Actions
{
    public class GoToMarkerAction : IAction
    {
        private readonly ThreadFixPlugin _threadFixPlugin;
        private readonly DTE2 _dte2;

        public GoToMarkerAction(ThreadFixPlugin threadFixPlugin)
        {
            _threadFixPlugin = threadFixPlugin;
            _dte2 = ServiceProvider.GlobalProvider.GetService(typeof(DTE)) as DTE2;
        }

        public void OnExecute(object sender, EventArgs args)
        {
            var selectedMarker = (args as GoToMarkerEventArgs).Marker;
            OpenFileAtLineNumber(selectedMarker.FilePath, selectedMarker.LineNumber.GetValueOrDefault());
        }

        private void OpenFileAtLineNumber(string filename, int lineNumber)
        {
            if (_dte2 != null)
            {
                try
                {
                    _dte2.ItemOperations.OpenFile(filename, Constants.vsViewKindTextView);
                    ((TextSelection)_dte2.ActiveDocument.Selection).GotoLine(lineNumber, false);
                }

                catch (Exception e)
                {
                    Debug.WriteLine("Unable to open file");
                }
            }
        }
    }

    public class GoToMarkerEventArgs : EventArgs
    {
        public GoToMarkerEventArgs(VulnerabilityMarker marker)
        {
            Marker = marker;
        }

        public VulnerabilityMarker Marker { get; set; }
    }
}
