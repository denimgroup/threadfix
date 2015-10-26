using System.ComponentModel.Composition;
using System.Windows.Media;
using Microsoft.VisualStudio.Text.Classification;
using Microsoft.VisualStudio.Utilities;

namespace marker_glyph
{
    #region Format definition
    /// <summary>
    /// Defines an editor format for the marker_glyph type that has a purple background
    /// and is underlined.
    /// </summary>
    [Export(typeof(EditorFormatDefinition))]
    [ClassificationType(ClassificationTypeNames = "marker_glyph")]
    [Name("marker_glyph")]
    [UserVisible(true)] //this should be visible to the end user
    [Order(Before = Priority.Default)] //set the priority to be after the default classifiers
    internal sealed class marker_glyphFormat : ClassificationFormatDefinition
    {
        /// <summary>
        /// Defines the visual format for the "marker_glyph" classification type
        /// </summary>
        public marker_glyphFormat()
        {
            this.DisplayName = "marker_glyph"; //human readable version of the name
            this.BackgroundColor = Colors.BlueViolet;
            this.TextDecorations = System.Windows.TextDecorations.Underline;
        }
    }
    #endregion //Format definition
}
