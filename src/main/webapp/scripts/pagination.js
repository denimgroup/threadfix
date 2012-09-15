/*====================================================
	- HTML Table Pagination
	- http://www.exforsys.com/tutorials/jquery/jquery-javascript-pagination.html
=====================================================*/

$(document).ready(function() {
	$('table.formattedTable').each(setupPagination($(this)));
});

function setupPagination(currenttable) {
	var currentPage = 0;
	var table = $(currenttable);
	var numPerPage;

	if (table.attr("itemsPerPage") != null
			|| typeof (table.attr("itemsPerPage")) != "undefined") {
		numPerPage = table.attr("itemsPerPage");
	} else {
		numPerPage = 101;
	}
    	
    	var repaginate = function() {
		var start = currentPage * numPerPage;
		var end = (currentPage + 1) * numPerPage;
		table.find('tbody tr.bodyRow')
				.slice(start, end).fadeIn().end()
				.slice(0, start).hide().end()
				.slice(end).hide().end();
		};

		var numRows = table.find('tbody tr.bodyRow').length;
		var numPages = Math.ceil(numRows / numPerPage);
        
        if (numPages > 1) {
        	var pager = $('<div class="pager"></div>');
	        
	        for (var page = 0; page < numPages; page++) {
	        	$('<span style="padding-left:10px" class="page-number">'
	        			+ (page + 1) + '</span>')
						.bind('click', { 'newPage' : page }, function(event) {
			          		currentPage = event.data['newPage'];
							repaginate();
							$(this).addClass('active').siblings()
									.removeClass('active');
						})
						.appendTo(pager).addClass('clickable');
        	}

	        pager.find('span.page-number:first').addClass('active');
			table.find('tfoot tr.footer td.pagination').html(pager);
	
			repaginate();
		} else {
			table.find('tfoot tr.footer td.pagination').html($(''));
		}
	}
