function reloadLeft() {
	submitAjaxReport('#leftReportForm', '#leftTileReport', '#leftViewMore');
}

function reloadRight() {
	submitAjaxReport('#rightReportForm', '#rightTileReport', '#rightViewMore');
}

function submitAjaxReport(formId,successDiv, viewMore) {
	
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
				if (text.indexOf("<img") !== -1) {
					$(viewMore).css("display","");
				}
				
				$("td").each(function(){
					if ($(this).attr("width") === "50%") {
						$(this).remove();
					}
				});
				$("img").each(function(){
					var src = $(this).attr("src");
					if (src.slice(src.length - 2) === "px") {
						$(this).remove();
					}
				});
				$("img").attr("style","");
				$("img").addClass("report-image");
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

addToDocumentReadyFunctions(reloadLeft);
addToDocumentReadyFunctions(reloadRight);
