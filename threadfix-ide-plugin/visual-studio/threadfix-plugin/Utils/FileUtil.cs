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
using EnvDTE;
using EnvDTE80;
using Microsoft.VisualStudio.Shell;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;

namespace DenimGroup.threadfix_plugin.Utils
{
    public static class FileUtil
    {
        public static readonly string ThreadFixDirectory = "ThreadFix/";

        public static DTE2 GetActiveIDE()
        {
            return Package.GetGlobalService(typeof(DTE)) as DTE2;
        }

        public static void SerializeMarkerData(ThreadFixPlugin threadFixPlugin)
        {
            var solutionName = GetSolutionName();
            if (string.IsNullOrEmpty(solutionName))
            {
                return;
            }

            var path = GetStoredPluginFilePath(solutionName);
            Directory.CreateDirectory(Path.GetDirectoryName(path));

            using (var fs = File.Open(path, FileMode.Create))
            using (var sw = new StreamWriter(fs))
            using (var jw = new JsonTextWriter(sw))
            {
                new JsonSerializer().Serialize(jw, new StoredPluginData { Markers = threadFixPlugin.Markers, SelectedAppIds = threadFixPlugin.SelectedAppIds });
            }
        }

        public static void DeserializeMarkerData(ThreadFixPlugin threadFixPlugin)
        {
            var solutionName = GetSolutionName();
            if (string.IsNullOrEmpty(solutionName))
            {
                return;
            }

            var path = GetStoredPluginFilePath(solutionName);
            if (File.Exists(path))
            {
                using (var file = File.OpenText(path))
                {
                    var storedData = (StoredPluginData) new JsonSerializer().Deserialize(file, typeof(StoredPluginData));
                    threadFixPlugin.Markers = storedData.Markers;
                    threadFixPlugin.SelectedAppIds = storedData.SelectedAppIds;
                }
            }
        }

        public static Dictionary<string, string> GetFileLookUp(IEnumerable<string> filenames)
        {
            var lookUp = new Dictionary<string, string>();
            foreach (var filename in filenames)
            {
                if(!string.IsNullOrEmpty(filename))
                {
                    lookUp.Add(filename, GetFullPath(filename));
                }
            }

            return lookUp;
        }

        public static void OpenFileAtLineNumber(string fullPath, int lineNumber)
        {
            var ide = GetActiveIDE();

            try
            {
                ide.ItemOperations.OpenFile(fullPath, Constants.vsViewKindTextView);
                if (lineNumber > 0)
                {
                    ((TextSelection)ide.ActiveDocument.Selection).GotoLine(lineNumber, false);
                }
            }

            catch (Exception)
            {

            }
        }

        private static string GetSolutionName()
        {
            return Path.GetFileNameWithoutExtension(GetActiveIDE().Solution.FullName);
        }

        private static string GetStoredPluginFilePath(string solutionName)
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), ThreadFixDirectory + solutionName);
        }

        private static string GetFullPath(string filename)
        {
            var ide = GetActiveIDE();

            foreach (Project proj in Projects(ide))
            {
                var path = Path.Combine(Path.GetDirectoryName(proj.FullName), filename.Substring(1).Replace(@"/", @"\"));
                if (File.Exists(path))
                {
                    return path;
                }
            }

            return null;
        }

        private static List<Project> Projects(DTE2 ide)
        {
            var projects = ide.Solution.Projects;
            var list = new List<Project>();
            var item = projects.GetEnumerator();

            while (item.MoveNext())
            {
                var project = item.Current as Project;
                if (project == null || string.IsNullOrEmpty(project.FullName))
                {
                    continue;
                }

                if (project.Kind == ProjectKinds.vsProjectKindSolutionFolder)
                {
                    list.AddRange(GetSolutionFolderProjects(project));
                }

                else
                {
                    list.Add(project);
                }
            }

            return list;
        }

        private static IEnumerable<Project> GetSolutionFolderProjects(Project solutionFolder)
        {
            var list = new List<Project>();
            for (var i = 1; i <= solutionFolder.ProjectItems.Count; i++)
            {
                var subProject = solutionFolder.ProjectItems.Item(i).SubProject;
                if (subProject == null || string.IsNullOrEmpty(subProject.FullName))
                {
                    continue;
                }

                // If this is another solution folder, do a recursive call, otherwise add
                if (subProject.Kind == ProjectKinds.vsProjectKindSolutionFolder)
                {
                    list.AddRange(GetSolutionFolderProjects(subProject));
                }

                else
                {
                    list.Add(subProject);
                }
            }

            return list;
        }
    }
}
