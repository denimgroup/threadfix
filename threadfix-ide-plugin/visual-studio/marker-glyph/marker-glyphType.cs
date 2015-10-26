using System.ComponentModel.Composition;
using Microsoft.VisualStudio.Text.Classification;
using Microsoft.VisualStudio.Utilities;

namespace marker_glyph
{
    internal static class marker_glyphClassificationDefinition
    {
        /// <summary>
        /// Defines the "marker_glyph" classification type.
        /// </summary>
        [Export(typeof(ClassificationTypeDefinition))]
        [Name("marker_glyph")]
        internal static ClassificationTypeDefinition marker_glyphType = null;
    }
}
