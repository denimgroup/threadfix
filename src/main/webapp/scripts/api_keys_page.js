function deleteKey(form) {
	return function() {
		if (confirm('Are you sure you want to delete this API Key?')) {
			basicPost($(form).attr("action"), form, '#tableDiv');
			for (var i = 0; i < modalRefreshFunctions.length; i++) {
				modalRefreshFunctions[i]();
			}
		}
		return false;
	};
}

function addHandlers() {
	$(".apiKeyDeleteButton").each(function() {
		$(this).on("click", deleteKey("#deleteForm" + $(this).attr("data-id")));
	});
}

addToDocumentReadyFunctions(addHandlers);

addToModalRefreshFunctions(addHandlers);