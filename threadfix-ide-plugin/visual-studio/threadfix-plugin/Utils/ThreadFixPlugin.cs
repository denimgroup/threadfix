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
using DenimGroup.threadfix_plugin.Controls;
using DenimGroup.threadfix_plugin.Data;
using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Linq;

namespace DenimGroup.threadfix_plugin.Utils
{
    public interface IThreadFixPlugin { }

    [Export(typeof(IThreadFixPlugin))]
    public class ThreadFixPlugin : IThreadFixPlugin
    {
        public ThreadFixToolWindow ToolWindow { get; set; }
        public OptionsPage Options { get; set; }
        public HashSet<string> SelectedAppIds { get; set; }
        public List<VulnerabilityMarker> Markers { get; set; }
        public Dictionary<string, List<VulnerabilityMarker>> MarkerLookUp { get; set; }
        public event EventHandler<EventArgs> MarkersUpdated;
        public Dictionary<string, string> FileLookUp { get; set; }

        public void ImportMarkers(HashSet<string> selectedAppIds, ThreadFixApi threadFixApi)
        {
            SelectedAppIds = selectedAppIds;
            Markers = threadFixApi.GetVulnerabilityMarkers(SelectedAppIds);
            FileLookUp = FileUtil.GetFileLookUp(new HashSet<string>(Markers.Select(m => m.FilePath)));
            MarkerLookUp = CreateMarkerLookUp();
        }

        public void ClearMarkers()
        {
            Markers = null;
            FileLookUp = null;
            MarkerLookUp = null;
        }

        public void UpdateMarkers()
        {
            if (MarkersUpdated != null)
            {
                MarkersUpdated(this, null);
            }
        }

        private Dictionary<string, List<VulnerabilityMarker>> CreateMarkerLookUp()
        {
            var lookUp = new Dictionary<string, List<VulnerabilityMarker>>();
            foreach (var marker in Markers)
            {
                var fullPath = FileLookUp[marker.FilePath];
                if (!string.IsNullOrEmpty(fullPath))
                {
                    fullPath = fullPath.ToLower();
                    if (!lookUp.ContainsKey(fullPath))
                    {
                        lookUp.Add(fullPath.ToLower(), new List<VulnerabilityMarker>());
                    }

                    lookUp[fullPath].Add(marker);
                }
            }

            return lookUp;
        }
    }
}
