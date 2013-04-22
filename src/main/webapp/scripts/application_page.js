
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
	
});