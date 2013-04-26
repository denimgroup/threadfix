
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
};

var addAppPageEvents = function () {
	$("#addWafButton").on("click", function() {
		if ($("#addWafDivInForm").attr("data-has-wafs")) {
			$("#addWaf").modal('show');
		} else {
			$("#createWaf").modal('show');
		}
	});
	
	$("#addDefectTrackerButton").on("click", function() {
		if ($("#addDefectTrackerDivInForm").attr("data-has-defect-trackers")) {
			$("#addDefectTracker").modal('show');
		} else {
			$("#createDefectTracker").modal('show');
		}
	});
	
	$("#jsonLink").on("click", function() {
		jsonTest($("#appDTDiv").attr("data-json-test-url"));
	});
	
	$("a.missingDefectTrackerMessage").on("click", function() {
		alert('Please add a Defect Tracker and try again.');
	});
};

var showSubmitLinks = function () {
	if ($("#submitDefectForm").attr("data-has-metadata")) {
		$(".submitDefectActionLink").css("display","");
		$(".missingDefectTrackerMessage").css("display","none");
	} else if ($("#editDefectTrackerButton").length != 0) {
		reloadDefectSubmissionDiv();
	}
	
	setTimeout(function () {
		if ($("#addDefectTrackerButton").length != 0) {
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
	
	addAppPageEvents();
	showSubmitLinks();
	addExpandsHandlers();
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
}

addToModalRefreshFunctions(addExpandsHandlers);
addToModalRefreshFunctions(showSubmitLinks);
addToModalRefreshFunctions(addAppPageEvents);
