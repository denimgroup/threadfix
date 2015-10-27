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
using System.Collections.Generic;
using System.ComponentModel;

namespace DenimGroup.threadfix_plugin.ViewModels
{
    public class ApplicationsViewModel : INotifyPropertyChanged
    {
        public List<ApplicationsViewModel> Children { get; set; }
        public bool IsInitiallySelected { get; set; }
        public string Name { get; set; }
        public string AppId { get; set; }
        public event PropertyChangedEventHandler PropertyChanged;

        private bool? _isChecked = false;
        private ApplicationsViewModel _parent;

        public ApplicationsViewModel(string name)
        {
            Name = name;
            Children = new List<ApplicationsViewModel>();
        }

        public void Initialize()
        {
            Children.ForEach(c =>
            {
                c._parent = this;
                c.Initialize();
            });
        }

        public bool? IsChecked
        {
            get { return _isChecked; }
            set { this.SetIsChecked(value, true, true); }
        }

        public static ApplicationsViewModel Create(string parentName, List<ApplicationInfo> applications, HashSet<string> selectedAppIds)
        {
            var model = new ApplicationsViewModel(parentName)
            {
                IsInitiallySelected = false
            };

            applications.ForEach(app => model.Children.Add(new ApplicationsViewModel(app.ApplicationName) 
            { 
                AppId = app.ApplicationId, 
            }));

            model.Initialize();

            model.Children.ForEach(child => { child.IsChecked = selectedAppIds != null && selectedAppIds.Contains(child.AppId); });

            return model;
        }

        void SetIsChecked(bool? value, bool updateChildren, bool updateParent)
        {
            if (value == _isChecked)
                return;

            _isChecked = value;

            if (updateChildren && _isChecked.HasValue)
                this.Children.ForEach(c => c.SetIsChecked(_isChecked, true, false));

            if (updateParent && _parent != null)
                _parent.VerifyCheckState();

            this.OnPropertyChanged("IsChecked");
        }

        void VerifyCheckState()
        {
            bool? state = null;
            for (int i = 0; i < this.Children.Count; ++i)
            {
                bool? current = this.Children[i].IsChecked;
                if (i == 0)
                {
                    state = current;
                }
                else if (state != current)
                {
                    state = null;
                    break;
                }
            }
            this.SetIsChecked(state, false, true);
        }

        void OnPropertyChanged(string prop)
        {
            if (this.PropertyChanged != null)
                this.PropertyChanged(this, new PropertyChangedEventArgs(prop));
        }
    }
}
