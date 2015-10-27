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
using DenimGroup.threadfix_plugin.Utils;
using Microsoft.VisualStudio.Text;
using Microsoft.VisualStudio.Text.Editor;
using Microsoft.VisualStudio.Text.Tagging;
using Microsoft.VisualStudio.Utilities;
using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;

namespace DenimGroup.threadfix_plugin.Controls
{
    public class MarkerTag : IGlyphTag { }

    public class MarkerTagger : ITagger<MarkerTag>, IDisposable
    {
        private readonly ThreadFixPlugin _threadFixPlugin;
        private readonly MarkerGlyphService _markerGlyphService;
        private readonly ITextBuffer _textBuffer;

        public MarkerTagger(ThreadFixPlugin threadFixPlugin, ITextBuffer textBuffer)
        {
            _threadFixPlugin = threadFixPlugin;
            _threadFixPlugin.MarkersUpdated += ThreadFixPlugin_MarkersUpdated;
            _markerGlyphService = new MarkerGlyphService(threadFixPlugin);
            _textBuffer = textBuffer;
        }

        IEnumerable<ITagSpan<MarkerTag>> ITagger<MarkerTag>.GetTags(NormalizedSnapshotSpanCollection spans)
        {
            foreach (var span in spans)
            {
                var lines = _markerGlyphService.GetMarkerLinesForFile(span.Snapshot);
                foreach (var line in lines)
                {
                    if (line != null)
                    {
                        yield return new TagSpan<MarkerTag>(new SnapshotSpan(line.Start, 1), new MarkerTag());   
                    }
                }
            }
        }

        public void ThreadFixPlugin_MarkersUpdated(object sender, EventArgs args)
        {
            var snapshot = _textBuffer.CurrentSnapshot;
            TagsChanged(this, new SnapshotSpanEventArgs(new SnapshotSpan(snapshot, new Span(0, snapshot.Length))));
        }

        public void Dispose()
        {
            _threadFixPlugin.MarkersUpdated -= ThreadFixPlugin_MarkersUpdated;
        }

#pragma warning disable 67
        // the Classifier tagger is translating buffer change events into TagsChanged events, so we don't have to
        public event EventHandler<SnapshotSpanEventArgs> TagsChanged;
#pragma warning restore

    }

    [Export(typeof(ITaggerProvider))]
    [ContentType("code")]
    [TagType(typeof(MarkerTag))]
    internal sealed class MarkerTaggerProvider : ITaggerProvider
    {
        [Import(typeof(IThreadFixPlugin))]
        internal ThreadFixPlugin ThreadFixPlugin;

        public ITagger<T> CreateTagger<T>(ITextBuffer buffer) where T : ITag
        {
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }

            return new MarkerTagger(ThreadFixPlugin, buffer) as ITagger<T>;
        }
    }
}
