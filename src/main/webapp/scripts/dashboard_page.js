function reloadLeft() {
	submitAjaxReport('#leftReportForm', '#leftTileReport');
}

function reloadRight() {
	submitAjaxReport('#rightReportForm', '#rightTileReport');
}

function submitAjaxReport(formId,successDiv) {
	
	$("#connectionUnavailableMessage").css("display", "none");
	
	$.ajax({
		type : "POST",
		url : $(formId).attr('action'),
		data : $(formId).serializeArray(),
		contentType : "application/x-www-form-urlencoded",
		dataType : "text",
		success : function(text) {
			
			 if ($.trim(text).slice(0,17) === "<body id=\"table\">") {
				$(successDiv).html(text);
			} else {
				try {
					var json = JSON.parse($.trim(text));
					if (json.isJSONRedirect) {
						window.location.href = json.redirectURL;
					}
				} catch (e) {
					$("#connectionUnavailableMessage").css("display", "");
				}
			}
		},
		error : function (xhr, ajaxOptions, thrownError){
			$("#connectionUnavailableMessage").css("display", "");
	    }
	});
	return false;
}

$(document).ready(function(){ 
	reloadLeft();
	reloadRight();
});
