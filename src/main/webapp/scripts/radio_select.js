$(document).ready(function() {
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