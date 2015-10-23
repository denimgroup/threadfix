using DenimGroup.threadfix_plugin.Data;
using DenimGroup.threadfix_plugin.ViewModels;
using System;
using System.Collections.Generic;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Navigation;
using System.Diagnostics;
using System.Windows.Input;

namespace DenimGroup.threadfix_plugin.Controls
{
    /// <summary>
    /// Interaction logic for ToolWindowControl.xaml
    /// </summary>
    public partial class ToolWindowControl : UserControl
    {
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

            Debug.WriteLine(selectedMarker.FilePath + "|" + selectedMarker.LineNumber);
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
}
