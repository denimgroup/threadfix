var addScanDeletes = function() {
	$(".scanDelete").each(function() {
		if (!$(this).attr("data-has-function")) {
			$(this).on("click", function() {
				if (confirm("Are you sure you want to delete this scan and all of its results? This will also delete any WAF rules and defects associated with orphaned vulnerabilities.")) {
					$("#" + $(this).attr("data-delete-form")).submit();
				}
			});
			$(this).attr("data-has-function","1");
		}
	});
	
	$(".scanQueueDelete").each(function() {
		if (!$(this).attr("data-has-function")) {
			$(this).on("click", function() {
				if (confirm("Are you sure you want to delete this scan queue task?")) {
					$("#" + $(this).attr("data-delete-form")).submit();
				}
			});
			$(this).attr("data-has-function","1");
		}
	});

    $(".scheduledScanDelete").each(function() {
        if (!$(this).attr("data-has-function")) {
            $(this).on("click", function() {
                if (confirm("Are you sure you want to delete this scheduled scan?")) {
                    $("#" + $(this).attr("data-delete-form")).submit();
                }
            });
            $(this).attr("data-has-function","1");
        }
    });
};

addToDocumentReadyFunctions(addScanDeletes);
addToModalRefreshFunctions(addScanDeletes);

function changeAbilityOfDaySelection()
{
    if (document.getElementById("frequency").value === "Weekly") {
        document.getElementById("selectedDay").disabled=false;
    } else {
        document.getElementById("selectedDay").disabled=true;
    }
}