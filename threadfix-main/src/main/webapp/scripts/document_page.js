var addDocFunctions = function() {
	$(".docDelete").each(function() {
		if (!$(this).attr("data-has-function")) {
			$(this).on("click", function() {
				if (confirm("Are you sure you want to delete this file?")) {
					$("#" + $(this).attr("data-delete-form")).submit();
				}
			});
			$(this).attr("data-has-function","1");
		}
	});
	
	$(".docDownload").each(function() {
			$(this).on("click", function() {
				$("#" + $(this).attr("data-download-form")).submit();
			});
	});	
	
};

addToDocumentReadyFunctions(addDocFunctions);
addToModalRefreshFunctions(addDocFunctions);

addToDocumentReadyFunctions(function () {
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
});
