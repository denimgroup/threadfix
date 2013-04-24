var lastReportId = 1;
var lastFormatId = 1;

function reload(url) { 
	submitAjaxReport(url, '#reportForm', '#formDiv', '#successDiv', lastReportId, lastFormatId);
}

function selectReportType(url, reportId) {
	$(".sidebar").removeClass("sidebar-active");
	$(".sidebar-arrow").removeClass("sidebar-active");
	$(".sidebar" + reportId).addClass("sidebar-active");
	$("#arrow" + reportId).addClass("sidebar-active");
	
	submitAjaxReport(url, '#reportForm', '#formDiv', '#successDiv', reportId, 1);
}

function submitAjaxReport(url, formId, formDiv, successDiv, reportId, formatId) {
	
	lastReportId = reportId;
	lastFormatId = formatId;
	
	$("#connectionUnavailableMessage").css("display", "none");
	$(".toRemove").remove();
	
	var formData = $(formId).serializeArray();
	
	formData[formData.length] = { name: 'reportId', value: reportId };
	formData[formData.length] = { name: 'formatId', value: formatId };
	
	if (formatId == 1) {
		$.ajax({
			type : "POST",
			url : url,
			data : formData,
			contentType : "application/x-www-form-urlencoded",
			dataType : "text",
			success : function(text) {
				
				if ($.trim(text).slice(0,22) === "<body id=\"formErrors\">") {
					$(formDiv).html(text);
				} else if ($.trim(text).slice(0,17) === "<body id=\"table\">") {
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
	} else {
		var input1 = $("<input>").attr("type", "hidden").attr("name", "formatId").addClass('toRemove').val(formatId);
		var input2 = $("<input>").attr("type", "hidden").attr("name", "reportId").addClass('toRemove').val(reportId);
		$(formId).append($(input1));
		$(formId).append($(input2));
		$(formId).submit();
	}
	setTimeout(function() {
		$(".modal").on("shown", function() {
	    	$(".modal-body").attr('tab-index','-1');
	    	$(".modal.in .modal-body input").first().focus();
	    });
	}, 1500);
	return false;
}

addToDocumentReadyFunctions(function() {
	var orgSelect = $("#orgSelect");
	var appSelect = $("#appSelect");
	orgSelect.on("change", function() { reload(orgSelect.attr("data-refresh-url")); });
	appSelect.on("change", function() { reload(orgSelect.attr("data-refresh-url")); });

	$(".sidebar").on("click", function() {
		selectReportType($(this).attr("data-url"), $(this).attr("data-report-id"));
	});

	if ($("#successDiv").attr('data-first-report') !== "") {
		var elementId = ".sidebar" + $("#successDiv").attr('data-first-report');
		$(elementId).click();
	} else {
		submitAjaxReport(orgSelect.attr("data-refresh-url"), '#reportForm', '#formDiv', '#successDiv', 1, 1);
	}
});
