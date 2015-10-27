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
using DenimGroup.threadfix_plugin.Extensions;
using Microsoft.VisualStudio.Text;
using System.Collections.Generic;

namespace DenimGroup.threadfix_plugin.Utils
{
    public class MarkerGlyphService
    {
        private readonly ThreadFixPlugin _threadFixPlugin;

        public MarkerGlyphService(ThreadFixPlugin threadFixPlugin)
        {
            _threadFixPlugin = threadFixPlugin;
        }

        public List<ITextSnapshotLine> GetMarkerLinesForFile(ITextSnapshot textSnapshot)
        {
            var lines = new List<ITextSnapshotLine>();

            if (_threadFixPlugin == null || _threadFixPlugin.MarkerLookUp == null)
            {
                return lines;
            }
            
            var filename = textSnapshot.TextBuffer.GetTextDocument().FilePath.ToLower();
            var markers = new List<VulnerabilityMarker>();
            
            if(_threadFixPlugin.MarkerLookUp.TryGetValue(filename, out markers))
            {
                foreach (var marker in markers)
                {
                    if (marker.LineNumber.HasValue)
                    {
                        lines.Add(textSnapshot.GetLineFromLineNumber(marker.LineNumber.Value - 1));
                    }
                }
            }

            return lines;
        }
    }
}
