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
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.ComponentModel.Design;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Task = System.Threading.Tasks.Task;

namespace DenimGroup.threadfix_plugin.Utils
{
    public interface IThreadFixPlugin { }

    [Export(typeof(IThreadFixPlugin))]
    public class ThreadFixPlugin : IThreadFixPlugin
    {
        private static readonly string InvalidUrlMessage = "Please provide a valid ThreadFix url in the options menu.";
        private static readonly string InvalidKeyMessage = "Please provide a valid ThreadFix api key in the options menu.";
        private readonly ThreadFixApi _threadFixApi;

        public OleMenuCommandService MenuCommandService { get; set; }
        public ThreadFixToolWindow ToolWindow { get; set; }
        public OptionsPage Options { get; set; }
        public List<ApplicationInfo> Applications { get; set; }
        public HashSet<string> SelectedAppIds { get; set; }
        public List<VulnerabilityMarker> Markers { get; set; }
        public Dictionary<string, List<VulnerabilityMarker>> MarkerLookUp { get; set; }
        public event EventHandler<EventArgs> MarkersUpdated;
        public Dictionary<string, string> FileLookUp { get; set; }

        public ThreadFixPlugin()
        {
            _threadFixApi = new ThreadFixApi(this);
        }

        public void LoadApplications(Action successCallback)
        {
            ValidateApiSettings();

            var task = Task.Factory.StartNew(() =>
            {
                Applications = _threadFixApi.GetThreadFixApplications();
            });

            RunThreadFixApiAsync(task, successCallback);
        }

        public void ImportMarkers(HashSet<string> selectedAppIds, Action successCallback)
        {
            ValidateApiSettings();

            var task = Task.Factory.StartNew(() =>
            {
                SelectedAppIds = selectedAppIds;
                Markers = _threadFixApi.GetVulnerabilityMarkers(SelectedAppIds);
                UpdateFileAndMarkerLookUp();
            });

            RunThreadFixApiAsync(task, successCallback);
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

        public void UpdateFileAndMarkerLookUp()
        {
            if (Markers != null)
            {
                FileLookUp = FileUtil.GetFileLookUp(new HashSet<string>(Markers.Select(m => m.FilePath)));
                MarkerLookUp = CreateMarkerLookUp();
            }
        }

        public void ToggleMenuCommands(bool enabled)
        {
            if (MenuCommandService != null)
            {
                ChangeCommand((int)PkgCmdIDList.cmdidImportMarkersCommand, enabled);
                ChangeCommand((int)PkgCmdIDList.cmdidClearMarkers, enabled);
            }
        }

        public void ShowErrorMessage(string message)
        {
            var uiShell = (IVsUIShell)ServiceProvider.GlobalProvider.GetService(typeof(SVsUIShell));
            var clsid = Guid.Empty;
            int result;
            Microsoft.VisualStudio.ErrorHandler.ThrowOnFailure(uiShell.ShowMessageBox(
                       0,
                       ref clsid,
                       "ThreadFix",
                       string.Format(CultureInfo.CurrentCulture, message, this.ToString()),
                       string.Empty,
                       0,
                       OLEMSGBUTTON.OLEMSGBUTTON_OK,
                       OLEMSGDEFBUTTON.OLEMSGDEFBUTTON_FIRST,
                       OLEMSGICON.OLEMSGICON_CRITICAL,
                       0,        // false
                       out result));
        }

        public void StorePluginData()
        {
            FileUtil.SerializeMarkerData(this);
        }

        public void RetrievePluginData()
        {
            FileUtil.DeserializeMarkerData(this);
        }

        private void RunThreadFixApiAsync(Task apiTask, Action success)
        {
            var context = SynchronizationContext.Current;
            apiTask.ContinueWith(result => 
            {
                context.Post(o => { success.Invoke(); }, null);
            }, TaskContinuationOptions.NotOnFaulted);
            apiTask.ContinueWith(error =>
            {
                ToggleMenuCommands(true);
                ShowErrorMessage(error.Exception.InnerException.Message);

            }, TaskContinuationOptions.OnlyOnFaulted);
        }

        private void ValidateApiSettings()
        {
            if (!ValidUrl(Options.ApiUrl))
            {
                ToggleMenuCommands(true);
                throw new ApplicationException(InvalidUrlMessage);
            }

            if (string.IsNullOrEmpty(Options.ApiKey))
            {
                ToggleMenuCommands(true);
                throw new ApplicationException(InvalidKeyMessage);
            }
        }

        private bool ValidUrl(string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                return false;
            }

            Uri result;
            return Uri.TryCreate(url, UriKind.Absolute, out result) && (result.Scheme == Uri.UriSchemeHttp || result.Scheme == Uri.UriSchemeHttps);
        }

        private void ChangeCommand(int commandId, bool enabled)
        {
            var command = new CommandID(GuidList.guidthreadfix_pluginCmdSet, commandId);
            var menuItem = MenuCommandService.FindCommand(command);
            if (menuItem != null)
            {
                menuItem.Enabled = enabled;
            }
        }

        private Dictionary<string, List<VulnerabilityMarker>> CreateMarkerLookUp()
        {
            var lookUp = new Dictionary<string, List<VulnerabilityMarker>>();
            foreach (var marker in Markers)
            {
                string fullPath;
                if (FileLookUp != null && FileLookUp.TryGetValue(marker.FilePath, out fullPath) && !string.IsNullOrEmpty(fullPath))
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
