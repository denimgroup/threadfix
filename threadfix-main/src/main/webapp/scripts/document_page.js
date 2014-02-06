var addDocFunctions = function() {
	$(".docDelete").each(function() {
		if (!$(this).attr("data-has-function")) {
			$(this).on("click", function() {
				if (confirm("Are you sure you want to delete this file?")) {
					$("#" + $(this).attr("data-delete-form")).submit();
				}
			});
			$(this).attr("data-has-function","1");
		}
	});
	
	$(".docDownload").each(function() {
			$(this).on("click", function() {
				$("#" + $(this).attr("data-download-form")).submit();
			});
	});	
	
};

addToDocumentReadyFunctions(addDocFunctions);
addToModalRefreshFunctions(addDocFunctions);
