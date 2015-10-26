using Microsoft.VisualStudio.Text.Editor;
using Microsoft.VisualStudio.Text.Formatting;
using Microsoft.VisualStudio.Text.Tagging;
using Microsoft.VisualStudio.Utilities;
using System;
using System.ComponentModel.Composition;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace DenimGroup.threadfix_plugin.Controls
{
    [Export(typeof(IGlyphFactoryProvider))]
    [Name("MarkerGlyph")]
    [Order(After = "VsTextMarker")]
    [ContentType("code")]
    [TagType(typeof(MarkerTag))]
    internal sealed class MarkerGlyphProvider : IGlyphFactoryProvider
    {
        public IGlyphFactory GetGlyphFactory(IWpfTextView view, IWpfTextViewMargin margin)
        {
            return new MarkerGlyphFactory();
        }
    }

    internal class MarkerGlyphFactory : IGlyphFactory
    {
        private static readonly string LogoResource = @"pack://application:,,,/Resources/DG_logo_mark_13x13.png";

        public UIElement GenerateGlyph(IWpfTextViewLine line, IGlyphTag tag)
        {
            if (tag == null || !(tag is MarkerTag))
            {
                return null;
            }

            /*System.Windows.Shapes.Ellipse ellipse = new Ellipse();
            ellipse.Fill = Brushes.LightBlue;
            ellipse.StrokeThickness = 2;
            ellipse.Stroke = Brushes.DarkBlue;
            ellipse.Height = 16.0;
            ellipse.Width = 16.0;

            return ellipse;*/

            var source = new BitmapImage(new Uri(LogoResource));
            var image = new Image()
            {
                Source = source
            };

            return image;
        }
    }
}
