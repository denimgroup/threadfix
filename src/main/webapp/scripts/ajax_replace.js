function submitAjaxModal(url, formId, formDiv, successDiv, modalName) {
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
			    });
			    $(modalName).modal('hide');
			    $(".clear-after-submit").val('');
			} else {
				try {
					var json = JSON.parse($.trim(text));
					if (json.isJSONRedirect) {
						window.location.href = json.redirectURL;
					}
				} catch (e) {
					history.go(0);
				}
			}
		},
		error : function (xhr, ajaxOptions, thrownError){
			history.go(0);
	    }
	});
	setTimeout(function() {
		$(".modal").on("shown", function() {
	    	$(".modal-body").attr('tab-index','-1');
	    	$(".modal.in .modal-body input").first().focus();
	    });
	}, 1500);
	return false;
}

function submitAjaxScan(url, formId, formDiv, channelId) {
	var fileInput = document.getElementById(formId);
	var file = fileInput.files[0];
	var formData = new FormData();
	formData.append('file', file);
	formData.append('channelId', $('#' + channelId).val());
	
	$.ajax({
		type : "POST",
		url : url,
		data : formData,
		contentType : "multipart/form-data",
		cache: false,
        contentType: false,
        processData: false,
		success : function(text) {
			
			if ($.trim(text).slice(0,22) === "<body id=\"formErrors\">") {
				$(formDiv).html(text);
			} else {
				try {
					var json = JSON.parse($.trim(text));
					if (json.isJSONRedirect) {
						window.location.href = json.redirectURL;
					}
				} catch (e) {
					history.go(0);
				}
			}
		},
		error : function (xhr, ajaxOptions, thrownError){
			history.go(0);
		}
	});
	setTimeout(function() {
		$(".modal").on("shown", function() {
			$(".modal-body").attr('tab-index','-1');
			$(".modal.in .modal-body input").first().focus();
		});
	}, 1500);
	return false;
}

function submitAjax(url, formId, formDiv, successDiv) {
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
				$(successDiv).html(text);
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
	setTimeout(function() {
		$(".modal").on("shown", function() {
	    	$(".modal-body").attr('tab-index','-1');
	    	$(".modal.in .modal-body input").first().focus();
	    });
	}, 1500);
	return false;
}

function submitVulnTableOperation(url, formDiv, successDiv) {
	
	var checkboxes = $(".vulnIdCheckbox").serializeArray();

	$.ajax({
		type : "POST",
		url : url,
		data : checkboxes,
		contentType : "application/x-www-form-urlencoded",
		dataType : "text",
		success : function(text) {
			
			if ($.trim(text).slice(0,22) === "<body id=\"formErrors\">") {
				$(formDiv).html(text);
			} else if ($.trim(text).slice(0,17) === "<body id=\"table\">") {
				$(successDiv).html(text);
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
	setTimeout(function() {
		$(".modal").on("shown", function() {
	    	$(".modal-body").attr('tab-index','-1');
	    	$(".modal.in .modal-body input").first().focus();
	    });
	}, 1500);
	return false;
}

function submitDefect(formId, formDiv, successDiv) {
	
	var checkboxes = $(".vulnIdCheckbox").serializeArray();
	var combo = $(formId).serializeArray();

	for(var i=0;i<checkboxes.length;i++)
	{
		combo.push(checkboxes[i]);
	}
	
	$.ajax({
		type : "POST",
		url : $(formId).attr('action'),
		data : combo,
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
					history.go(0);
				}
			}
		},
		error : function (xhr, ajaxOptions, thrownError){
			history.go(0);
		}
	});
	setTimeout(function() {
		$(".modal").on("shown", function() {
	    	$(".modal-body").attr('tab-index','-1');
	    	$(".modal.in .modal-body input").first().focus();
	    });
	}, 1500);
	return false;
}

function basicGet(url, target) {
	$.ajax({
		type : "GET",
		url : url,
		dataType : "text",
		success : function(text) {
			if ($.trim(text).slice(0,17) === "<body id=\"table\">") {
				$(target).html(text);
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
	setTimeout(function() {
		$(".modal").on("shown", function() {
	    	$(".modal-body").attr('tab-index','-1');
	    	$(".modal.in .modal-body input").first().focus();
	    });
	}, 100);
    return false;
}

function basicPost(url, formId, target) {
	$.ajax({
		type : "POST",
		url : url,
		data : $(formId).serializeArray(),
		contentType : "application/x-www-form-urlencoded",
		dataType : "text",
		success : function(text) {
			if ($.trim(text).slice(0,17) === "<body id=\"table\">") {
				$(target).html(text);
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
	setTimeout(function() {
		$(".modal").on("shown", function() {
	    	$(".modal-body").attr('tab-index','-1');
	    	$(".modal.in .modal-body input").first().focus();
	    });
	}, 1500);
	return false;
}

// These are for the application page.
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

function addWafAndRefresh(url) {
	return submitAjaxModal(url, '#addWafForm', '#addWaf', '#appWafDiv', '#addWaf');
}

function createWafAndRefresh(url) {
	return submitAjaxModal(url, '#wafForm', '#createWaf', '#appWafDiv', '#createWaf');
}

function updateWafAndRefresh(url, wafForm, editWafDiv) {
	return submitAjaxModal(url, wafForm, editWafDiv, '#appWafDiv', editWafDiv);
}

function switchTabs(url) {
	return basicGet(url, '#tabsDiv');
}

function createDTAndRefresh(url) {
	$.ajax({
		type : "POST",
		url : url,
		data : $('#createDefectTrackerForm').serializeArray(),
		contentType : "application/x-www-form-urlencoded",
		dataType : "text",
		success : function(text) {
			if ($.trim(text).slice(0,22) === "<body id=\"formErrors\">") {
				$('#dtFormDiv').html(text);
			} else if ($.trim(text).slice(0,17) === "<body id=\"table\">") {
				$('#addDefectTracker').html(text);
				$('#defectTableDiv').html(text);
			    $('#createDefectTracker').modal('hide');
			    $('#addDefectTracker').modal('show');
			    
			} else {$("#nameInput").focus();
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
	setTimeout(function() {
		$(".modal").on("shown", function() {
	    	$(".modal-body").attr('tab-index','-1');
	    	$(".modal.in .modal-body input").first().focus();
	    });
	}, 1500);
    return false;
}

function addDTAndRefresh(url) {
	return submitAjaxModal(url, '#addDTForm', '#addDTFormDiv', '#appDTDiv', '#addDefectTracker');
}

function deleteWaf(url) {
	if (confirm('Are you sure you want to delete this WAF? This won\'t work if the WAF has applications attached.'))
		return basicPost(url, '#deleteForm', '#defectTableDiv');
	return false;
}

function deleteDefectTracker(url) {
	if (confirm('Are you sure you want to delete this Defect Tracker? You will lose all associated Defects.'))
		return basicPost(url, '#deleteForm', '#defectTableDiv');
	return false;
}

function toggleExpandable(expandable, caret) {
	$(expandable).collapse('toggle');
	if ($(caret).attr('class').indexOf('expanded') == -1) {
		$(caret).addClass('expanded');
	} else {
		$(caret).removeClass('expanded');
	}
}

function toggleExpandableWithReport(expandable, caret, reportDiv) {
	toggleExpandable(expandable, caret);
	
	if ($("#" + reportDiv)[0] && !$("#" + reportDiv).attr('data-loaded')) {
		$.ajax({
			type : "GET",
			url : $("#" + reportDiv).attr('data-url'),
			dataType : "text",
			success : function(text) {
				 if ($.trim(text).slice(0,17) === "<body id=\"table\">") {
					 $("#" + reportDiv).html(text);
					 $("#" + reportDiv).attr('data-loaded', '1');
				} else {
					$("#connectionUnavailableMessage").css("display", "");
				}
			},
			error : function (xhr, ajaxOptions, thrownError){
				$("#connectionUnavailableMessage").css("display", "");
		    }
		});
	}
}

var documentReadyFunctions = [
	function() {
		$(".focus").focus();
		$(".modal");
		setTimeout(function() {
			$(".modal").on("shown", function() {
		    	$(".modal-body").attr('tab-index','-1');
		    	$(".modal.in .modal-body input").first().focus();
		    });
		}, 1500);
	},
	function() {
		if(top != self) top.location.replace(location);
	}
];

function addToDocumentReadyFunctions(readyFunction) {
	documentReadyFunctions[documentReadyFunctions.length] = readyFunction;
}

function timeout1500(timeoutFunction) {
	setTimeout(timeoutFunction, 1500);
}

$(document).ready(function(){
	for (var i = 0; i < documentReadyFunctions.length; i++) {
		documentReadyFunctions[i]();
	}
});
