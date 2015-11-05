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
using System.Threading;

namespace DenimGroup.threadfix_plugin.Actions
{
    public class ImportAction : IAction
    {
        private readonly ThreadFixPlugin _threadFixPlugin;
        private readonly ViewModelService _viewModelService;

        public ImportAction(ThreadFixPlugin threadFixPlugin)
        {
            _threadFixPlugin = threadFixPlugin;
            _viewModelService = new ViewModelService(_threadFixPlugin);
        }

        public void OnExecute(object sender, EventArgs args)
        {
            _threadFixPlugin.ToggleMenuCommands(false);
            _threadFixPlugin.LoadApplications(() =>
            {
                var applicationsWindow = new ApplicationsWindow();
                applicationsWindow.ApplicationsSelected += OnAppsSelected;

                applicationsWindow
                    .SetViewModel(_viewModelService.GetApplicationsViewModel(_threadFixPlugin.Applications, _threadFixPlugin.SelectedAppIds))
                    .ShowDialog();

                _threadFixPlugin.ToggleMenuCommands(true);
            });
        }

        private void OnAppsSelected(object sender, ApplicationsSelectedEventArgs args)
        {
            _threadFixPlugin.ToggleMenuCommands(false);
            _threadFixPlugin.ImportMarkers(_viewModelService.GetSelectedAppIds(args.Model), () => 
            {
                _threadFixPlugin.UpdateMarkers();
                _threadFixPlugin.ToggleMenuCommands(true);

                new ShowAction(_threadFixPlugin).OnExecute(this, null);
            });
        }
    }
}
