var addScanDeletes = function() {
	$(".scanDelete").on("click", function() {
		if (confirm("Are you sure you want to delete this scan and all of its results? This will also delete any WAF rules and defects associated with orphaned vulnerabilities.")) {
			$("#" + $(this).attr("data-delete-form")).submit();
		}
	});
};

addToDocumentReadyFunctions(addScanDeletes);
addToModalRefreshFunctions(addScanDeletes);
