function submitAjaxModal(url, formId, formDiv, successDiv, modalName, collapsible) {
	$.ajax({
		type : "POST",
		url : url,
		data : $(formId).serializeArray(),
		contentType : "application/x-www-form-urlencoded",
		dataType : "text",
		success : function(text) {
			
			if ($.trim(text).slice(0,22) === "<body id=\"formErrors\">") {
				$(formDiv).html(text);
			} else if ($.trim(text).slice(0,17) === "<body id=\"table\">") {
				$(modalName).on('hidden', function () {
					$(successDiv).html(text);
					$(collapsible).collapse('show');
			    });
			    $(modalName).modal('hide');
			    $(".clear-after-submit").val('');
			} else {
				try {
					var json = JSON.parse(text);
					alert(json.error);
				} catch (e) {
					history.go(0);
				}
			}
		},
		error : function (xhr, ajaxOptions, thrownError){
			history.go(0);
	    }
	});
}

function reloadTable() {
	
	var tableDiv = $("#teamTable");
	$.ajax({
		type : "GET",
		url : tableDiv.attr("data-url"),
		success : function(text) {
			tableDiv.html(text);
		},
		error : function (xhr, ajaxOptions, thrownError){
			history.go(0);
	    }
	});
}

$(document).ready(function(){ 
	reloadTable();
	
	$("#submitTeamModal").click(function() {
		submitAjaxModal($("#organizationForm").attr("action"),'#organizationForm', '#formDiv', '#teamTable', '#myTeamModal','');
	});
	
});
