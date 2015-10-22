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
using System;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.ComponentModel.Design;
using Microsoft.Win32;
using Microsoft.VisualStudio;
using Microsoft.VisualStudio.Shell.Interop;
using Microsoft.VisualStudio.OLE.Interop;
using Microsoft.VisualStudio.Shell;
using DenimGroup.threadfix_plugin.Actions;
using DenimGroup.threadfix_plugin.Controls;
using DenimGroup.threadfix_plugin.Utils;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;

namespace DenimGroup.threadfix_plugin
{
    /// <summary>
    /// This is the class that implements the package exposed by this assembly.
    ///
    /// The minimum requirement for a class to be considered a valid package for Visual Studio
    /// is to implement the IVsPackage interface and register itself with the shell.
    /// This package uses the helper classes defined inside the Managed Package Framework (MPF)
    /// to do it: it derives from the Package class that provides the implementation of the 
    /// IVsPackage interface and uses the registration attributes defined in the framework to 
    /// register itself and its components with the shell.
    /// </summary>
    // This attribute tells the PkgDef creation utility (CreatePkgDef.exe) that this class is
    // a package.
    [PackageRegistration(UseManagedResourcesOnly = true)]
    // This attribute is used to register the information needed to show this package
    // in the Help/About dialog of Visual Studio.
    [InstalledProductRegistration("#110", "#112", "1.0", IconResourceID = 400)]
    // This attribute is needed to let the shell know that this package exposes some menus.
    [ProvideMenuResource("Menus.ctmenu", 1)]
    [Guid(GuidList.guidthreadfix_pluginPkgString)]
    [ProvideOptionPage(typeof(OptionsPage), "ThreadFix", "Settings", 0, 0, true)]
    public sealed class threadfix_pluginPackage : Package
    {
        private readonly ThreadFixPlugin _threadFixPlugin;

        /// <summary>
        /// Default constructor of the package.
        /// Inside this method you can place any initialization code that does not require 
        /// any Visual Studio service because at this point the package object is created but 
        /// not sited yet inside Visual Studio environment. The place to do all the other 
        /// initialization is the Initialize method.
        /// </summary>
        public threadfix_pluginPackage()
        {
            Debug.WriteLine(string.Format(CultureInfo.CurrentCulture, "Entering constructor for: {0}", this.ToString()));
            _threadFixPlugin = new ThreadFixPlugin();
        }

        /////////////////////////////////////////////////////////////////////////////
        // Overridden Package Implementation
        #region Package Members

        /// <summary>
        /// Initialization of the package; this method is called right after the package is sited, so this is the place
        /// where you can put all the initialization code that rely on services provided by VisualStudio.
        /// </summary>
        protected override void Initialize()
        {
            Debug.WriteLine (string.Format(CultureInfo.CurrentCulture, "Entering Initialize() of: {0}", this.ToString()));
            base.Initialize();

            // Global plugin state
            _threadFixPlugin.Options = (OptionsPage)GetDialogPage(typeof(OptionsPage));

            // Add our command handlers for menu (commands must exist in the .vsct file)
            OleMenuCommandService mcs = GetService(typeof(IMenuCommandService)) as OleMenuCommandService;
            if ( null != mcs )
            {
                // Create the command for the menu item.
                AddMenuItemCallback((int)PkgCmdIDList.cmdidImportMarkersCommand, mcs, new ImportAction(_threadFixPlugin));
                AddMenuItemCallback((int)PkgCmdIDList.cmdidClearMarkers, mcs, new ClearAction(_threadFixPlugin));
                AddMenuItemCallback((int)PkgCmdIDList.cmdidShowToolWindow, mcs, new ShowAction(_threadFixPlugin));
            }
#if DEBUG
            // Disable ssl certificate validation for debugging purposes
            System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) { return true; };

            Debug.WriteLine("API Key: " + _threadFixPlugin.Options.ApiKey);
            Debug.WriteLine("API Url: " + _threadFixPlugin.Options.ApiUrl);
#endif
        }

        private void AddMenuItemCallback(int commandId, OleMenuCommandService commandService, IAction callback)
        {
            CommandID menuCommandID = new CommandID(GuidList.guidthreadfix_pluginCmdSet, commandId);
            MenuCommand menuItem = new MenuCommand(callback.OnExecute, menuCommandID);
            commandService.AddCommand(menuItem);
        }

        #endregion
    }
}
