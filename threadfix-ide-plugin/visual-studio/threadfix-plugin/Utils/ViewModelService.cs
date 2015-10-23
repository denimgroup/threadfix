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
using DenimGroup.threadfix_plugin.ViewModels;
using System.Collections.Generic;
using System.Linq;

namespace DenimGroup.threadfix_plugin.Utils
{
    public class ViewModelService
    {
        private static readonly string CWEBaseUrl = "http://cwe.mitre.org/data/definitions/";
        private readonly ThreadFixPlugin _threadFixPlugin;

        public ViewModelService(ThreadFixPlugin threadFixPlugin)
        {
            _threadFixPlugin = threadFixPlugin;
        }

        public List<ApplicationsViewModel> GetApplicationsViewModel(List<ApplicationInfo> applications)
        {
            var applicationsViewModel = new List<ApplicationsViewModel>();

            if(applications == null || applications.Count == 0)
            {
                return applicationsViewModel;
            }

            var appsByTeam = applications.GroupBy(app => app.OrganizationName).ToDictionary(g => g.Key, g => g.ToList());

            foreach(var item in appsByTeam.OrderBy(kvp => kvp.Key))
            {
                applicationsViewModel.Add(ApplicationsViewModel.Create(item.Key, item.Value));
            }

            return applicationsViewModel;
        }

        public HashSet<string> GetSelectedAppIds(List<ApplicationsViewModel> applications)
        {
            var ids = new HashSet<string>();

            if (applications == null || applications.Count == 0)
            {
                return ids;
            }

            foreach (var app in applications)
            {
                ids.UnionWith(app.Children.Where(c => c.IsChecked.GetValueOrDefault()).Select(c => c.AppId));
            }

            return ids;
        }

        public List<VulnerabilityMarker> GetVulnerabilityViewModel(List<VulnerabilityMarker> vulnerabilities)
        {
            if (vulnerabilities == null)
            {
                return new List<VulnerabilityMarker>();
            }

            foreach (var vulnerability in vulnerabilities)
            {
                if (!string.IsNullOrEmpty(vulnerability.GenericVulnId))
                {
                    vulnerability.CWEUrl = CWEBaseUrl + vulnerability.GenericVulnId;
                }
            }

            return vulnerabilities;
        }
    }
}
