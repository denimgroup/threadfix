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
using DenimGroup.threadfix_plugin.ViewModels;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Windows;
using System.Linq;

namespace DenimGroup.threadfix_plugin.Controls
{
    /// <summary>
    /// Interaction logic for ApplicationsWindow.xaml
    /// </summary>
    public partial class ApplicationsWindow : Window
    {
        public event EventHandler<ApplicationsSelectedEventArgs> ApplicationsSelected;

        public ApplicationsWindow()
        {
            InitializeComponent();
        }

        public ApplicationsWindow SetViewModel(List<ApplicationsViewModel> viewModel)
        {
            ApplicationsTree.DataContext = viewModel;
            return this;
        }

        private void Ok_Clicked(object sender, RoutedEventArgs args)
        {
            Close();

            if (ApplicationsSelected != null)
            {
                ApplicationsSelected(this, new ApplicationsSelectedEventArgs(ApplicationsTree.Items.OfType<ApplicationsViewModel>().ToList()));
            }
        }

        private void Cancel_Clicked(object sender, RoutedEventArgs args)
        {
            Close();
        }
    }

    public class ApplicationsSelectedEventArgs : EventArgs
    {
        public ApplicationsSelectedEventArgs(List<ApplicationsViewModel> viewModel)
        {
            Model = viewModel;
        }

        public List<ApplicationsViewModel> Model { get; set; }
    }
}
