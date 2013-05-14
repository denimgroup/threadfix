function delay(timeoutFunction) {
	return function() {
		setTimeout(timeoutFunction, 1100);
	};
}


function modalFocusTimeout() {
	setTimeout(function() {
		$(".modal").on("shown", function() {
	    	$(".modal-body").attr('tab-index','-1');
	    	$(".modal.in .modal-body input, .modal.in .modal-body textarea").first().focus();
	    });
	}, 1500);
}

var modalRefreshFunctions = [ 
	delay(addModalSubmitEvents),
	function () { addFormEvents(); },
	function () { modalFocusTimeout(); }
];

var modalFailureFunctions = [
    delay(addModalSubmitEvents),
    function () {
    	$(".modal-body").attr('tab-index','-1');
		$(".modal.in .modal-body input").first().focus();
    }
];

function submitAjaxModalFunction(url, formId, formDiv, successDiv, modalName, expandable, successClick) {
	return function () {
		var successFunction = function() {
			if (successClick !== "#undefined") {
				setTimeout(function(){$(successClick).click();}, 200);
			}
			if (expandable !== "#undefined") {
				$(expandable).collapse('toggle'); 
			}
			for (var i = 0; i < modalRefreshFunctions.length; i++) {
				modalRefreshFunctions[i]();
			}
		};
		
		submitAjaxModalWithSuccessFunction(url, formId, formDiv, successDiv, modalName, successFunction); 
	};
}

function submitAjaxModalWithSuccessFunction(url, formId, formDiv, successDiv, modalName, successFunction) {
	$.ajax({
		type : "POST",
		url : url,
		data : $(formId).serializeArray(),
		contentType : "application/x-www-form-urlencoded",
		dataType : "text",
		success : function(text) {
			
			if ($.trim(text).slice(0,22) === "<body id=\"formErrors\">") {
				$(formDiv).html(text);
				for (var i = 0; i < modalFailureFunctions.length; i++) {
					modalFailureFunctions[i]();
				}
			} else if ($.trim(text).slice(0,17) === "<body id=\"table\">") {
				$(modalName).on('hidden', function () {
					$(successDiv).html(text);
					successFunction();
				});
				$(modalName).modal('hide');
				$(".clear-after-submit").val('');
				$(".clear-after-submit").prop("checked",false)
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
	return false;
}

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
	modalFocusTimeout();
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
	modalFocusTimeout();
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
	modalFocusTimeout();
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
	modalFocusTimeout();
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
	modalFocusTimeout();
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
				for (var i = 0; i < modalRefreshFunctions.length; i++) {
					modalRefreshFunctions[i]();
				}
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
	modalFocusTimeout();
	return false;
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
			    for (var i = 0; i < modalRefreshFunctions.length; i++) {
					modalRefreshFunctions[i]();
				}
			} else {$("#nameInput").focus();
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
	modalFocusTimeout();
    return false;
}

function deleteWaf(url) {
	if (confirm('Are you sure you want to delete this WAF?'))
		return basicPost(url, '#deleteForm', '#defectTableDiv');
	return false;
}

function deleteDefectTracker(url, id) {
	if (confirm('Are you sure you want to delete this Defect Tracker? You will lose all associated Defects.')) {
		$('#' + id).closest(".modal").modal('hide');
		basicPost(url, '#deleteForm', '#defectTableDiv');
	}
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

// This function makes some assumptions about how your modal is laid out:
// 1. It is contained in a form which is to be submitted, and has an appropriate action attribute
// 2. That form is enclosed in a parent div which can be replaced with any failure content
// 3. var form = element.closest("form");, var div = form.closest("div");, var modal = element.closest(".modal"); all work
// 4. the item has a data-success-div which is to be replaced
//
// This allows you to add the class and the success div and not care about anything else
function addModalSubmitEvents() {
	$(".modalSubmit").each(function() {
		var element = $(this);
		if (!element.attr('data-has-function')) {
			var form = element.closest("form");
			if (!form || form.length === 0) { form = $("#" + element.attr("data-form")); };
			var div = $("#" + element.attr("data-form-div"));
			if (!div || div.length === 0) { div = form.closest("div"); };
			var modal = element.closest(".modal");
			var submitFunction = submitAjaxModalFunction(
					form.attr("action"), 
					"#" + form.attr("id"), 
					"#" + div.attr("id"), 
					"#" + element.attr("data-success-div"), 
					"#" + modal.attr("id"),
					'#' + element.attr("data-expandable"),
					'#' + element.attr("data-success-click"));
			form.keypress(function(e) {
			    if (e.which == 13){
			    	e.preventDefault();
			    	submitFunction();
			    }
			});
			element.click(function() {
				submitFunction();
				return false;
			});
			element.attr("data-has-function","1");
		}
	});
}

function addAppSelectFunctions() {
	$(".selectFiller").each(function() {
		var element = $(this);
		if (!element.attr('data-has-function')) {
			var targetSelect = '#' + element.attr('data-select-target');
			
			var changeFunction = function() {
				var selectedElement = $("#" + element.attr('id')).find(":selected");
				$(targetSelect).html('');
				var objs = JSON.parse(selectedElement.attr('data-select-items'));
				for (index in objs) {
					var app = objs[index];
					if (app.id !== "do-not-use") {
						$(targetSelect).append($('<option>', {
							value: app.id,
							text : app.name
						}));
					}
				};
			};
			
			element.on("change", changeFunction);
			changeFunction();
			
			element.attr("data-has-function","1");
		}
	});
}

var addHeaderFunctions = function() {
	$(".clickInsideLink").on("click", function() {
		window.location.href = $(this).children("a").attr("href");
	});
};

var addFormEvents = function() {
	$(".set-value-on-load").each(function(){
		if ($(this).attr("data-value") === "true") {
			$(this).attr("checked", "checked");
		}
	});
	
	$("textarea").each(function() {
		if ($(this).attr('data-max-length')) {
			$(this).bind('input propertychange', function() {  
		        var maxLength = $(this).attr('data-max-length');  
		        if ($(this).val().length > maxLength) {  
		            $(this).val($(this).val().substring(0, maxLength));
		            $("#" + $(this).attr('data-error')).css("display","");
		        } else {
		        	$("#" + $(this).attr('data-error')).css("display","none");
		        }
		    });
		}
	});
};

// this is a list of functions that get executed in $(document).ready
var documentReadyFunctions = [
	function() {
		$(".focus").focus();
		$(".modal");
		modalFocusTimeout();
	},
	function() {
		if(top != self) top.location.replace(location);
	},
	addModalSubmitEvents,
	addAppSelectFunctions,
	addHeaderFunctions,
	addFormEvents
];

// helper method to add to the document ready stuff
function addToDocumentReadyFunctions(readyFunction) {
	documentReadyFunctions[documentReadyFunctions.length] = readyFunction;
}

function addToModalRefreshFunctions(readyFunction) {
	modalRefreshFunctions[modalRefreshFunctions.length] = readyFunction;
}

// Executes documentReadyFunctions.
$(document).ready(function(){
	for (var i = 0; i < documentReadyFunctions.length; i++) {
		documentReadyFunctions[i]();
	}
});
