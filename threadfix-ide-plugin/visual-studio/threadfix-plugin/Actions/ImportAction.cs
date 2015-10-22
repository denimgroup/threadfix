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
using System.Diagnostics;

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
            // TODO: validate url and api key before making calls to threadfix
            var applications = _threadFixApi.GetThreadFixApplications();

            var applicationsWindow = new ApplicationsWindow();
            applicationsWindow.ApplicationsSelected += OnAppsSelected;

            applicationsWindow
                .SetViewModel(_viewModelService.GetApplicationsViewModel(applications))
                .ShowDialog();
        }

        private void OnAppsSelected(object sender, ApplicationsSelectedEventArgs args)
        {
            // TODO: show some kind of loading spinner here. if time permits set up async http calls
            _threadFixPlugin.SelectedAppIds = _viewModelService.GetSelectedAppIds(args.Model);
            _threadFixPlugin.Markers = _threadFixApi.GetVulnerabilityMarkers(_threadFixPlugin.SelectedAppIds);

            var showToolWindow = new ShowAction(_threadFixPlugin);
            showToolWindow.OnExecute(this, null);
        }
    }
}
