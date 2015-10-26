using DenimGroup.threadfix_plugin.Data;
using DenimGroup.threadfix_plugin.Extensions;
using Microsoft.VisualStudio.Text;
using System.Collections.Generic;

namespace DenimGroup.threadfix_plugin.Utils
{
    public class MarkerGlyphService
    {
        private readonly ThreadFixPlugin _threadFixPlugin;

        public MarkerGlyphService(ThreadFixPlugin threadFixPlugin)
        {
            _threadFixPlugin = threadFixPlugin;
        }

        public List<ITextSnapshotLine> GetMarkerLinesForFile(ITextSnapshot textSnapshot)
        {
            var lines = new List<ITextSnapshotLine>();

            if (_threadFixPlugin == null || _threadFixPlugin.MarkerLookUp == null)
            {
                return lines;
            }
            
            var filename = textSnapshot.TextBuffer.GetTextDocument().FilePath.ToLower();
            var markers = new List<VulnerabilityMarker>();
            
            if(_threadFixPlugin.MarkerLookUp.TryGetValue(filename, out markers))
            {
                foreach (var marker in markers)
                {
                    if (marker.LineNumber.HasValue)
                    {
                        lines.Add(textSnapshot.GetLineFromLineNumber(marker.LineNumber.Value - 1));
                    }
                }
            }

            return lines;
        }
    }
}
