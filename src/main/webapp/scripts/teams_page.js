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
		$("#myTeamModal").on("shown", function() {
			$("#teamNameInput").focus();
		});
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
				if ($(targetDiv).attr('class').indexOf('in') === -1) {
					$(caretDiv).addClass('expanded');
					$(targetDiv).css("min-height:250px;");
					$('body').animate({
				         scrollTop: $(this).offset().top
				     }, 2);
					$(targetDiv).collapse('show');
				} else {
					$(caretDiv).removeClass('expanded');
					$(targetDiv).collapse('hide');
				}
				
				
				
				if ($(reportDiv)[0] && !$(reportDiv).attr('data-loaded')) {
					$.ajax({
						type : "GET",
						url : $(reportDiv).attr('data-url'),
						dataType : "text",
						success : function(text) {
							 if ($.trim(text).slice(0,17) === "<body id=\"table\">") {
								 $(reportDiv).html(text);
								 $(reportDiv).find("td[width='50%']").remove();
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
	
	$("#expandAllButton").on("click",function() {
		$(".expandableTrigger").each(function(){
			var target = $("#" + $(this).closest("tr").attr("data-target-div"));
			if (target.attr('class').indexOf("in") == -1) {
				$("#" + $(this).closest("tr").attr("data-caret-div")).click();
			}
		});
	});
	
	$("#collapseAllButton").on("click",function() {
		$(".expandableTrigger").each(function(){
			var target = $("#" + $(this).closest("tr").attr("data-target-div"));
			if (target.attr('class').indexOf("in") != -1) {
				$("#" + $(this).closest("tr").attr("data-caret-div")).click();
			}
		});
	});
}

addToDocumentReadyFunctions(function(){
	reloadTable();
	addExpandsHandlers();
});

addToModalRefreshFunctions(addExpandsHandlers);
