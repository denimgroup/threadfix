
function switchDTModals() {
    $("#addDefectTracker").modal('hide');
    $("#createDefectTracker").modal('show');
    return false;
};

function switchWafModals() {
    $("#addWaf").modal('hide');
    $("#createWaf").modal('show');
    return false;
};

var reloadDefectSubmissionDiv = function () {
	var tableDiv = $("#submitDefectFormDiv");
	
	if (!$("#submitDefectForm").attr("data-has-metadata")) {
		if (tableDiv) {
			$.ajax({
				type : "GET",
				url : tableDiv.attr("data-refresh-url"),
				success : function(text) {
					tableDiv.html(text);
					if ($("#submitDefectForm").attr("data-has-metadata")) {
						$(".submitDefectActionLink").css("display","");
						$(".missingDefectTrackerMessage").css("display","none");
					} else {
						$(".submitDefectActionLink").css("display","none");
						$(".missingDefectTrackerMessage").css("display","");
					}
				},
				error : function (xhr, ajaxOptions, thrownError){
					history.go(0);
			    }
			});
		}
	}
};

var defectTrackerAddFunction = function() {
	if ($("#addDefectTrackerDivInForm").attr("data-has-defect-trackers")) {
		$("#addDefectTracker").modal('show');
	} else {
		$("#createDefectTracker").modal('show');
	}
};

var addAppPageEvents = function () {
	$("#addWafButton").on("click", function() {
		if ($("#addWafDivInForm").attr("data-has-wafs")) {
			$("#addWaf").modal('show');
		} else {
			$("#createWaf").modal('show');
		}
	});
	
	var showEditModal = function() { $("#editApplicationModal").modal('show'); };
	
	$("#addWaf").on('hidden', showEditModal);
	$("#createWaf").on('hidden', showEditModal);
	$("#addDefectTracker").on('hidden', showEditModal);
	
	$("#addDefectTrackerButton").on("click", defectTrackerAddFunction);
	
	$("#addWafButton").on("click", function() {
		$("#editApplicationModal").modal('hide');
	});
	$("#editWafButton").on("click", function() {
		$("#editApplicationModal").modal('hide');
	});
	
	$("#editDefectTrackerButton").on("click", function() {
		$("#editApplicationModal").modal('hide');
	});
	$("#addDefectTrackerButton").on("click", function() {
		$("#editApplicationModal").modal('hide');
	});
	
	$("#jsonLink").on("click", function() {
		jsonTest($("#appDTDiv").attr("data-json-test-url"));
	});
	
	$("a.missingDefectTrackerMessage").on("click", defectTrackerAddFunction);
	
	if (!$("#expandAllVulns").attr("data-has-function")) {
		$("#expandAllVulns").on("click",function() {
			$("td.vulnSectionHeader .caret-right").each(function() {
				if ($(this).attr("class").indexOf("expanded") == -1) {
					$(this).click();
				}
			});
		});
		$("#expandAllVulns").attr("data-has-function","1");
	}
	if (!$("#collapseAllVulns").attr("data-has-function")) {
		$("#collapseAllVulns").on("click",function() {
			if ($(".vulnSectionHeader").size() == 0) {
				$("#vulnTabLink").click();
			} else {
				$("td.vulnSectionHeader .caret-right").each(function() {
					if ($(this).attr("class").indexOf("expanded") != -1) {
						$(this).click();
					}
				});
			}
		});
		$("#collapseAllVulns").attr("data-has-function","1");
	}
};

var showSubmitLinks = function () {
	if ($("#submitDefectForm").attr("data-has-metadata")) {
		$(".submitDefectActionLink").css("display","");
		$(".missingDefectTrackerMessage").css("display","none");
	} else if ($("#editDefectTrackerButton").length != 0) {
		reloadDefectSubmissionDiv();
	}
	
	setTimeout(function () {
		if ($("#editDefectTrackerButton").length != 0) {
			reloadDefectSubmissionDiv();
		}
	}, 1100);
};

addToDocumentReadyFunctions(function () {
	$('#vulnTab').button('toggle');
	toggleFilters(false, null, null);
	
	// Manual finding form
	
	current = -1;
	
	$("#cv_select").change(function(){
		var selectedItem = $("#cv_select option:selected").val();
		$("#txtSearch").val(selectedItem);
	});
	
	$("#url_select").change(function(){
		var selectedItem = $("#url_select option:selected").val();
		$("#urlSearch").val(selectedItem);
	});
	
	var choice = $('input:radio[name=group]:checked').val();
	if(choice == 'dynamic') {
		$('.dynamic').show();
		$('.static').hide();
	}
	if(choice == 'static') {
		$('.static').show();
		$('.dynamic').hide();
	}
	
	$('input:radio[name=group]').click(function(){
		var choice = $('input:radio[name=group]:checked').val();
		if(choice == 'dynamic') {
			$('.dynamic').show();
			$('.static').hide();
		}
		if(choice == 'static') {
			$('.static').show();
			$('.dynamic').hide();
		}
	});
	
	if ($("#headerDiv").attr("data-wait-for-refresh")) {
		var poll = function() {
			setTimeout(function(){
				$.ajax({
					url: $("#headerDiv").attr("data-refresh-url"), 
					success: function(data) {
						if (data.wait) {
							poll();
						} else if (data.isJSONRedirect) {
							window.location.href = data.redirectURL;
							return;
						}
					}, 
					dataType: "json", 
				});
			}, 1000);
		};
		poll();
	}
	
	addAppPageEvents();
	showSubmitLinks();
	addExpandsHandlers();
	reloadLeft();
	reloadRight();
});

function addExpandsHandlers() {
	$(".expandableTrigger").each(function() {
		var element = $(this);
		if (!element.attr('data-has-function')) {
			var parentTr = element.closest("tr");
			var targetDiv = '#' + parentTr.attr('data-target-div');
			var caretDiv = '#' + parentTr.attr('data-caret-div');
			
			element.on("click", function() {
				$(targetDiv).collapse('toggle');
				if ($(caretDiv).attr('class').indexOf('expanded') == -1) {
					$(caretDiv).addClass('expanded');
				} else {
					$(caretDiv).removeClass('expanded');
				}
			});
			
			element.attr("data-has-function","1");
		}
	});
	
	$(".vulnSectionHeader").on("click", function () {
		
		var parentTr = $(this).closest("tr");
		
		if (parentTr.attr("data-expanded") === "0") {
			$("." + parentTr.attr("data-toggle-class")).removeClass("defaultHide");
			parentTr.attr("data-expanded", "1");
			$("#" + parentTr.attr("data-caret")).addClass("expanded");
			parentTr.attr("data-has-function", "1");
		} else {
			$("." + parentTr.attr("data-toggle-class")).addClass("defaultHide");
			parentTr.attr("data-expanded", "0");
			$("#" + parentTr.attr("data-caret")).removeClass("expanded");
			parentTr.attr("data-has-function", "1");
		}
	});

	var isChecked = function(element, index, array) {
		return $(element).attr("checked") === "checked";
	};

	$(".categoryCheckbox").each(function () {
		var target = $(this).attr("data-target-class");
		var outerThis = $(this);
		$(".vulnIdCheckbox." + target).on("change", function() {
				
			if ($(".vulnIdCheckbox." + target).toArray().every(isChecked)) {
				$(outerThis).attr("checked", "checked");
			} else {
				$(outerThis).removeAttr("checked"); 
			}
			
			if ($(".vulnIdCheckbox").toArray().every(isChecked) && $(".categoryCheckbox").toArray().every(isChecked)) {
				$("#chkSelectAll").attr("checked", "checked");
			} else {
				$("#chkSelectAll").removeAttr("checked");
			}
		});
	});
	
	$(".categoryCheckbox").on("click", function () {
		var target = $(this).attr("data-target-class");
		var outerThis = $(this);

		if (outerThis.attr("checked") === "checked") {
			$(".vulnIdCheckbox." + target).attr("checked", "checked");
			if ($(".vulnIdCheckbox").toArray().every(isChecked) && $(".categoryCheckbox").toArray().every(isChecked)) {
				$("#chkSelectAll").attr("checked", "checked");
			}
		} else {
			$("#chkSelectAll").removeAttr("checked");
			$(".vulnIdCheckbox." + target).removeAttr("checked");
		}
	});
	
	$("#chkSelectAll").on("click", function() {
		if ($(this).attr("checked") === "checked") {
			$(".categoryCheckbox").each(function() {
				$(this).attr("checked", "checked");
			});
			$(".vulnIdCheckbox").each(function() {
				$(this).attr("checked", "checked");
			});
		} else {
			$(".categoryCheckbox").each(function() {
				$(this).removeAttr("checked");
			});
			$(".vulnIdCheckbox").each(function() {
				$(this).removeAttr("checked");
			});
		}
	});
}

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

addToModalRefreshFunctions(addExpandsHandlers);
addToModalRefreshFunctions(showSubmitLinks);
addToModalRefreshFunctions(addAppPageEvents);
