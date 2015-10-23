using System;
using System.Collections;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Windows;
using System.Runtime.InteropServices;
using Microsoft.VisualStudio.Shell.Interop;
using Microsoft.VisualStudio.Shell;

namespace DenimGroup.threadfix_plugin.Controls
{
    [Guid("D95E0E1B-21FE-4487-8B04-B7D5AB563BA7")]
    public class ThreadFixToolWindow : ToolWindowPane
    {
        private static readonly string WindowTitle = "ThreadFix";

        public ThreadFixToolWindow()
            : base(null)
        {
            Caption = WindowTitle;
            Content = new ToolWindowControl();
        }
    }
}
