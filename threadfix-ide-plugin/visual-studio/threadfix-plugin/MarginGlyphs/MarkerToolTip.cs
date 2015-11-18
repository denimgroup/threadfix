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
using DenimGroup.threadfix_plugin.MarginGlyph;
using DenimGroup.threadfix_plugin.Utils;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Text;
using Microsoft.VisualStudio.Text.Editor;
using Microsoft.VisualStudio.Text.Formatting;
using Microsoft.VisualStudio.Text.Tagging;
using Microsoft.VisualStudio.Utilities;
using System;
using System.Collections.Generic;
using System.ComponentModel.Composition;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Threading;

namespace DenimGroup.threadfix_plugin.MarginGlyphs
{
    [Order]
    [ContentType("code")]
    [Name("MarkerToolTipHandlerProvider")]
    [Export(typeof(IGlyphMouseProcessorProvider))]
    public class MarkerToolTipHandlerProvider : IGlyphMouseProcessorProvider
    {
        [Import(typeof(IThreadFixPlugin))]
        internal ThreadFixPlugin ThreadFixPlugin = null;

        [Import]
        public IViewTagAggregatorFactoryService ViewTagAggregatorFactoryService { get; set; }

        public IMouseProcessor GetAssociatedMouseProcessor(IWpfTextViewHost wpfTextViewHost, IWpfTextViewMargin margin)
        {
            return new MarkerToolTipHandler(this, ThreadFixPlugin, wpfTextViewHost, margin);
        }
    }

    public class MarkerToolTipHandler : MouseProcessorBase
    {
        private readonly ThreadFixPlugin _threadFixPlugin;
        private readonly IWpfTextViewHost _textViewHost;
        private readonly IWpfTextViewMargin _margin;
        private readonly ITagAggregator<MarkerTag> _glyphTagAggregator;
        private readonly Popup _popup;
        private DispatcherTimer _mouseHoverTimer;
        private ITextViewLine _lastHoverPosition;
        private ITextViewLine _currentlyHoveringLine;

        public MarkerToolTipHandler(MarkerToolTipHandlerProvider provider, ThreadFixPlugin threadFixPlugin, IWpfTextViewHost wpfTextViewHost, IWpfTextViewMargin margin)
        {
            _threadFixPlugin = threadFixPlugin;
            _textViewHost = wpfTextViewHost;
            _margin = margin;
            _glyphTagAggregator = provider.ViewTagAggregatorFactoryService.CreateTagAggregator<MarkerTag>(wpfTextViewHost.TextView);
            _popup = new Popup
            {
                IsOpen = false,
                Visibility = Visibility.Hidden
            };

            _textViewHost.Closed += (sender, e) => _glyphTagAggregator.Dispose();
        }

        public override void PostprocessMouseEnter(MouseEventArgs e)
        {
            EnableToolTip();
        }

        public override void PostprocessMouseLeave(MouseEventArgs e)
        {
            DisableToolTip();
        }

        public override void PreprocessMouseMove(MouseEventArgs e)
        {
            var textViewLine = GetTextViewLine(GetMouseLocationInTextView(e).Y);
            if (_mouseHoverTimer != null)
            {
                if (textViewLine != _currentlyHoveringLine)
                {
                    _currentlyHoveringLine = null;
                    HideToolTip();
                }

                _mouseHoverTimer.Start();
            }
        }

        private void EnableToolTip()
        {
            if (_mouseHoverTimer == null)
            {
                _mouseHoverTimer = new DispatcherTimer(TimeSpan.FromMilliseconds(150), DispatcherPriority.Normal, ShowToolTip, _margin.VisualElement.Dispatcher);
            }

            _mouseHoverTimer.Start();
        }

        private void DisableToolTip()
        {
            if (_mouseHoverTimer != null)
            {
                _mouseHoverTimer.Stop();
            }

            HideToolTip();
            _lastHoverPosition = null;
        }

        private void HideToolTip()
        {
            _popup.Child = null;
            _popup.IsOpen = false;
            _popup.Visibility = Visibility.Hidden;
        }

        private void ShowToolTip(object sender, EventArgs e)
        {
            if (_mouseHoverTimer == null || _textViewHost.IsClosed || !_mouseHoverTimer.IsEnabled || !_margin.Enabled)
            {
                return;
            }

            var point = Mouse.GetPosition(_margin.VisualElement);
            var textViewLine = _textViewHost.TextView.TextViewLines.GetTextViewLineContainingYCoordinate(point.Y + _textViewHost.TextView.ViewportTop);

            if (textViewLine == _lastHoverPosition)
            {
                return;
            }

            _lastHoverPosition = textViewLine;

            if (_lastHoverPosition == null)
            {
                return;
            }

            string toolTip = null;
            foreach (var tag in GetTagsForLine(textViewLine))
            {
                if (!string.IsNullOrEmpty(tag.ToolTip))
                {
                    toolTip = tag.ToolTip;
                }
            }

            if (!string.IsNullOrEmpty(toolTip))
            {
                var block = new TextBlock
                {
                    Text = toolTip,
                    Name = "MarkerToolTip"
                };

                block.SetResourceReference(TextBlock.ForegroundProperty, VsBrushes.ScreenTipTextKey);

                var border = new Border
                {
                    Padding = new Thickness(1.0),
                    BorderThickness = new Thickness(1.0),
                    Child = block
                };

                border.SetResourceReference(Border.BorderBrushProperty, VsBrushes.ScreenTipBorderKey);
                border.SetResourceReference(Border.BackgroundProperty, VsBrushes.ScreenTipBackgroundKey);

                _popup.Child = border;
                _popup.Placement = PlacementMode.Relative;
                _popup.PlacementTarget = _margin.VisualElement;
                _popup.HorizontalOffset = 0.0;
                _popup.VerticalOffset = textViewLine.Bottom - _textViewHost.TextView.ViewportTop;
                _popup.IsOpen = true;
                _popup.Visibility = Visibility.Visible;

                _currentlyHoveringLine = textViewLine;
            }
        }

        private IEnumerable<MarkerTag> GetTagsForLine(ITextViewLine line)
        {
            var visualBuffer = _textViewHost.TextView.TextViewModel.VisualBuffer;
            var textBuffer = _textViewHost.TextView.TextBuffer;
            foreach (var mapping in _glyphTagAggregator.GetTags(line.ExtentAsMappingSpan))
            {
                var tag = mapping.Tag as MarkerTag;
                if (tag != null)
                {
                    SnapshotPoint? visualPoint = mapping.Span.Start.GetPoint(visualBuffer, PositionAffinity.Predecessor);
                    SnapshotPoint? textPoint = mapping.Span.Start.GetPoint(textBuffer, PositionAffinity.Predecessor);
                    if (visualPoint.HasValue && visualPoint.HasValue && visualPoint.Value >= line.Start && visualPoint.Value <= line.End)
                        yield return tag;
                }
            }
        }

        private Point GetMouseLocationInTextView(MouseEventArgs e)
        {
            var textView = _textViewHost.TextView;
            var position = e.GetPosition(textView.VisualElement);
            position.Y += textView.ViewportTop;
            position.X += textView.ViewportLeft;
            return position;
        }

        private ITextViewLine GetTextViewLine(double y)
        {
            var textView = _textViewHost.TextView;
            var textViewLine = textView.TextViewLines.GetTextViewLineContainingYCoordinate(y);
            if (textViewLine == null)
            {
                textViewLine = (y <= textView.TextViewLines[0].Top) ? textView.TextViewLines.FirstVisibleLine : textView.TextViewLines.LastVisibleLine;
            }

            return textViewLine;
        }
    }
}
