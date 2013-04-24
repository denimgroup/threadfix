addToDocumentReadyFunctions(function() {
	$(".scanDelete").on("click", function() {
		if (confirm("Are you sure you want to delete this scan?")) {
			$("#" + $(this).attr("data-delete-form")).submit();
		}
	});
});
