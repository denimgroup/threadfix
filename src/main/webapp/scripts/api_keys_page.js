function submitNewKeyModal() {
	submitAjaxModal($("#newKeyForm").attr("action"), '#newKeyForm', '#formDiv', '#tableDiv', '#newKeyModalDiv');
	$('#newKeyModalDiv').on('hide', timeout1500(addHandlers));
}

function submitEditKeyModal(id) {
	return function() {
		submitAjaxModal($("#editKeyForm" + id).attr("action"), '#editKeyForm' + id, '#formDiv' + id, '#tableDiv', '#editKeyModal' + id);
	    $('#editKeyModal' + id).on('hide', timeout1500(addHandlers));
	};
}

function deleteKey(form) {
	return function() {
		if (confirm('Are you sure you want to delete this API Key?')) {
			basicPost($(form).attr("action"), form, '#tableDiv');
			timeout1500(addHandlers);
		}
		return false;
	};
}

function addHandlers() {
	$("#newKeyForm").keypress(function(e) {
	    if (e.which == 13){
	    	submitNewKeyModal();
	    }
	});
	
	$(".submitKeyModalEdit").each(function() {
		var id = $(this).attr("data-id");
		$(this).on("click", submitEditKeyModal(id));
		$(this).keypress(function(e) {
		    if (e.which == 13){
		    	submitEditKeyModal(id);
		    }
		});
	});
	
	$(".apiKeyDeleteButton").each(function() {
		$(this).on("click", deleteKey("#deleteForm" + $(this).attr("data-id")));
	});
	
	$("#submitKeyModalCreate").on("click", submitNewKeyModal);
}

addToDocumentReadyFunctions(addHandlers);

