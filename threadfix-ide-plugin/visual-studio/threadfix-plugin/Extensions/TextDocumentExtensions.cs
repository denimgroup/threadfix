using Microsoft.VisualStudio.Text;

namespace DenimGroup.threadfix_plugin.Extensions
{
    public static class TextDocumentExtensions
    {
        public static ITextDocument GetTextDocument(this ITextBuffer textBuffer)
        {
            ITextDocument doc;
            var result = textBuffer.Properties.TryGetProperty<ITextDocument>(typeof(ITextDocument), out doc);
            return result ? doc : null;
        }
    }
}
