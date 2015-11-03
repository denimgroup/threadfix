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
using DenimGroup.threadfix_plugin.Utils;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DenimGroup.threadfix_plugin.Actions
{
    public class ImportAction : IAction
    {
        private readonly ThreadFixPlugin _threadFixPlugin;
        private readonly ViewModelService _viewModelService;
        private readonly ThreadFixApi _threadFixApi;

        public ImportAction(ThreadFixPlugin threadFixPlugin)
        {
            _threadFixPlugin = threadFixPlugin;
            _viewModelService = new ViewModelService(_threadFixPlugin);
            _threadFixApi = new ThreadFixApi(_threadFixPlugin);
        }

        public void OnExecute(object sender, EventArgs args)
        {
            var applications = _threadFixApi.GetThreadFixApplications();

            var applicationsWindow = new ApplicationsWindow();
            applicationsWindow.ApplicationsSelected += OnAppsSelected;

            applicationsWindow
                .SetViewModel(_viewModelService.GetApplicationsViewModel(applications, _threadFixPlugin.SelectedAppIds))
                .ShowDialog();
        }

        private void OnAppsSelected(object sender, ApplicationsSelectedEventArgs args)
        {
            _threadFixPlugin.ToggleMenuCommands(false);
            var loading = new LoadingWindow();
            loading.Show();
            var context = SynchronizationContext.Current;
            var importMarkers = ImportMarkersAysnc(_viewModelService.GetSelectedAppIds(args.Model));

            importMarkers.ContinueWith((result) =>
            {
                context.Post(o => 
                {
                    _threadFixPlugin.UpdateMarkers();

                    var showToolWindow = new ShowAction(_threadFixPlugin);
                    showToolWindow.OnExecute(this, null);

                    loading.Close();
                    _threadFixPlugin.ToggleMenuCommands(true);
                }, null);
            });
        }

        private Task ImportMarkersAysnc(HashSet<string> selectedAppIds)
        {
            return Task.Factory.StartNew(() =>
            {
                _threadFixPlugin.ImportMarkers(selectedAppIds, _threadFixApi);
            });
        }
    }
}
