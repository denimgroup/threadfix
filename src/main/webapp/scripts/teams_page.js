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

var showModalIfAttributePresent = function() {
	if ($("#addTeamModalButton").attr("data-default-show")) {
		$("#addTeamModalButton").click();
	}
};

function reloadTable() {
	
	var tableDiv = $("#teamTable");
	$.ajax({
		type : "GET",
		url : tableDiv.attr("data-url"),
		success : function(text) {
			tableDiv.html(text);
			addModalSubmitEvents();
			addExpandsHandlers();
			showModalIfAttributePresent();
		},
		error : function (xhr, ajaxOptions, thrownError){
			history.go(0);
	    }
	});
}

function addExpandsHandlers() {
	$(".expandableTrigger").each(function() {
		var element = $(this);
		if (!element.attr('data-has-function')) {
			var parentTr = element.closest("tr");
			var targetDiv = '#' + parentTr.attr('data-target-div');
			var caretDiv = '#' + parentTr.attr('data-caret-div');
			var reportDiv = '#' + parentTr.attr('data-report-div');
			
			element.on("click", function() {
				$(targetDiv).collapse('toggle');
				if ($(caretDiv).attr('class').indexOf('expanded') == -1) {
					$(caretDiv).addClass('expanded');
				} else {
					$(caretDiv).removeClass('expanded');
				}
				
				if ($(reportDiv)[0] && !$(reportDiv).attr('data-loaded')) {
					$.ajax({
						type : "GET",
						url : $(reportDiv).attr('data-url'),
						dataType : "text",
						success : function(text) {
							 if ($.trim(text).slice(0,17) === "<body id=\"table\">") {
								 $(reportDiv).html(text);
								 $(reportDiv).attr('data-loaded', '1');
							} else {
								$("#connectionUnavailableMessage").css("display", "");
							}
						},
						error : function (xhr, ajaxOptions, thrownError){
							$("#connectionUnavailableMessage").css("display", "");
					    }
					});
				}
			});
			
			element.attr("data-has-function","1");
		}
	});
}

addToDocumentReadyFunctions(function(){ 
	reloadTable();
	addExpandsHandlers();
});

addToModalRefreshFunctions(addExpandsHandlers);
