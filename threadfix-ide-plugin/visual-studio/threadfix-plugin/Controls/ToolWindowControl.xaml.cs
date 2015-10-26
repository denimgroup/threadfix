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
using DenimGroup.threadfix_plugin.Actions;
using DenimGroup.threadfix_plugin.Data;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Navigation;

namespace DenimGroup.threadfix_plugin.Controls
{
    /// <summary>
    /// Interaction logic for ToolWindowControl.xaml
    /// </summary>
    public partial class ToolWindowControl : UserControl
    {
        public event EventHandler<GoToMarkerEventArgs> MarkerSelected;

        public ToolWindowControl()
        {
            InitializeComponent();
        }

        public ToolWindowControl SetViewModel(List<VulnerabilityMarker> vulnerabilities)
        {
            VulnerabilityList.ItemsSource = vulnerabilities;
            ResourceFilter.Text = "";
            CollectionView view = (CollectionView)CollectionViewSource.GetDefaultView(VulnerabilityList.ItemsSource);
            view.Filter = VulnerabilityFilter;

            return this;
        }

        public void List_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            var selectedMarker = ((ListViewItem)sender).Content as VulnerabilityMarker;
            if (MarkerSelected != null)
            {
                MarkerSelected(this, new GoToMarkerEventArgs(selectedMarker));
            }
        }

        public void Vulnerability_RequestNavigate(object sender, RequestNavigateEventArgs e)
        {
            if (e.Uri != null && !string.IsNullOrEmpty(e.Uri.AbsoluteUri))
            {
                Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri));
                e.Handled = true;
            }
        }

        public void ClearList()
        {
            VulnerabilityList.ItemsSource = null;
            ResourceFilter.Text = "";
        }

        public void Filter_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (VulnerabilityList.ItemsSource != null)
            {
                CollectionViewSource.GetDefaultView(VulnerabilityList.ItemsSource).Refresh();
            }
        }

        private bool VulnerabilityFilter(object item)
        {
            if (string.IsNullOrEmpty(ResourceFilter.Text))
            {
                return true;
            }

            return ((item as VulnerabilityMarker).FilePath.IndexOf(ResourceFilter.Text, StringComparison.OrdinalIgnoreCase) >= 0);
        }
    }

    public class StringToUriConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value == null || value.ToString().Length == 0)
            {
                return null;
            }

            return new Uri(value as string);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value;
        }
    }
}
