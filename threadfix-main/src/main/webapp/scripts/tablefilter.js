/*====================================================
	- HTML Table Filter Generator v1.6
	- By Max Guglielmi
	- mguglielmi.free.fr/scripts/TableFilter/?l=en
	- please do not change this comment
	- don't forget to give some credit... it's always
	good for the author
	- Special credit to Cedric Wartel and 
	cnx.claude@free.fr for contribution and 
	inspiration
=====================================================*/
function toggleFilters(show){
	if (show == true){
		grabEBI("showFilters").style.display = "none";
		grabEBI("vulnerabilityFilters").style.display = "";
		ClearFilters();
	} else {
		grabEBI("showFilters").style.display = "";
		grabEBI("vulnerabilityFilters").style.display = "none";
		ClearFilters();
	}
}

function ClearFilters(){
	grabEBI("severityFilterInput").value = "";
	grabEBI("locationFilterInput").value = "";
	grabEBI("parameterFilterInput").value = "";
	grabEBI("descriptionFilterInput").value = "";
	Filter();
}

function ToggleCheckboxes(tableId, cb_col){
	var chkAll = grabEBI("chkSelectAll");
	var checked = chkAll.checked;
	var t = grabEBI(tableId);
	var rows = grabTag(t,"tr");
	
	for(var k=1; k<rows.length - 1; k++)
	{
		var checkbox = rows[k].children[cb_col].children[0];
		if (checkbox != null && checkbox.type == 'checkbox' && $(rows[k]).hasClass('bodyRow')) {  
			checkbox.checked = checked;
		} 
	}
}

function CheckSelectAll(tableId, cb_col){
	var chkAll = grabEBI("chkSelectAll");
	var checked = chkAll.checked;
	
	if (checked) {
		var t = grabEBI(tableId);
		var rows = grabTag(t,"tr");
		
		for(var k=1; k<rows.length - 1; k++)
		{
			var checkbox = rows[k].children[cb_col].children[0];
			if (checkbox != null && checkbox.type == 'checkbox' && $(rows[k]).hasClass('bodyRow')) {  
				if (!checkbox.checked) {
					chkAll.checked = false;
					break;
				}
			} 
		}
	} else {
		var allChecked = true;
		var t = grabEBI(tableId);
		var rows = grabTag(t,"tr");
		
		for(var k=1; k<rows.length - 1; k++)
		{
			var checkbox = rows[k].children[cb_col].children[0];
			if (checkbox != null && checkbox.type == 'checkbox' && $(rows[k]).hasClass('bodyRow')) {  
				if (!checkbox.checked) {
					allChecked = false;
					break;
				}
			}
		}
		if (allChecked) {
			chkAll.checked = true;
		}
	}
}

function Filter()
/*====================================================
	- Filtering fn
	- gets search strings from SearchFlt array
	- retrieves data from each td in every single tr
	and compares to search string for current
	column
	- tr is hidden if all search strings are not 
	found
=====================================================*/
{	
	var id = "vulnerabilities";
	var ncells = getCellsNb(id);
	var SearchFlt = new Array();

	SearchFlt.push("");
	SearchFlt.push("");
	SearchFlt.push("descriptionFilterInput");
	SearchFlt.push("severityFilterInput");
	SearchFlt.push("locationFilterInput");
	SearchFlt.push("parameterFilterInput");
	for (var i = SearchFlt.length; i < ncells; i++) {
		SearchFlt.push("");
	}
	
	var t = grabEBI(id);
	t.tf_ref_row = 1;
	var SearchArgs = new Array();
	var totrows = getRowsNb(id);
	var ematch = false;
	
	for(var i=0; i<SearchFlt.length; i++) {
		if ((SearchFlt[i] != null) && (SearchFlt[i] != "")) {
			SearchArgs.push( (grabEBI(SearchFlt[i]).value).toLowerCase() );
		} else {
			SearchArgs.push("");
		}
	}
	
	var start_row = t.tf_ref_row;
	var row = grabTag(t,"tr");

	for(var k=start_row; k<row.length; k++)
	{
		if($(row[k]).hasClass("footer"))
			continue;
		/*** if table already filtered some rows are not visible ***/
		if(row[k].style.display == "none") row[k].style.display = "";
		
		var cell = getChildElms(row[k]).childNodes;
		var nchilds = cell.length;

		if(nchilds == ncells)// checks if row has exact cell #
		{
			var cell_value = new Array();
			var occurence = new Array();
			var isRowValid = true;

			for(var j=0; j<nchilds; j++)// this loop retrieves cell data
			{
				var cell_data = getCellText(cell[j]).toLowerCase();
				cell_value.push(cell_data);
				
				if(SearchArgs[j]!="")
				{
					var num_cell_data = parseFloat(cell_data);
					
					if(/<=/.test(SearchArgs[j]) && !isNaN(num_cell_data)) // first checks if there is an operator (<,>,<=,>=)
					{
						num_cell_data <= parseFloat(SearchArgs[j].replace(/<=/,"")) ? occurence[j] = true : occurence[j] = false;
					}
					
					else if(/>=/.test(SearchArgs[j]) && !isNaN(num_cell_data))
					{
						num_cell_data >= parseFloat(SearchArgs[j].replace(/>=/,"")) ? occurence[j] = true : occurence[j] = false;
					}
					
					else if(/</.test(SearchArgs[j]) && !isNaN(num_cell_data))
					{
						num_cell_data < parseFloat(SearchArgs[j].replace(/</,"")) ? occurence[j] = true : occurence[j] = false;
					}
										
					else if(/>/.test(SearchArgs[j]) && !isNaN(num_cell_data))
					{
						num_cell_data > parseFloat(SearchArgs[j].replace(/>/,"")) ? occurence[j] = true : occurence[j] = false;
					}					
					
					else 
					{						
						// Improved by Cedric Wartel (cwl)
						// automatic exact match for selects and special characters are now filtered
						// modif cwl : exact match automatique sur les select
						var regexp;
						if(ematch){
							regexp = new RegExp('(^)'+regexpEscape(SearchArgs[j])+'($)',"gi");
						}
						else {
							regexp = new RegExp(regexpEscape(SearchArgs[j]),"gi");
						}
						occurence[j] = regexp.test(cell_data);
					}
				}//if SearchArgs
			}//for j
			
			for(var z=0; z<nchilds; z++)
			{
				if(SearchArgs[z]!="" && !occurence[z]) isRowValid = false;
			}//for t
			
		}//if
		
		if(!isRowValid)
		{ 
			row[k].style.display = "none";
			$(row[k]).removeClass('bodyRow');
			var checkbox = row[k].children[5].children[0];
			if (checkbox != null && checkbox.type == 'checkbox') {     
				checkbox.checked = false;
			}
		} else {
			row[k].style.display = "";
			$(row[k]).addClass('bodyRow');
			var checkbox = row[k].children[5].children[0];
			if (checkbox != null && checkbox.type == 'checkbox' && grabEBI("chkSelectAll").checked) {     
				checkbox.checked = true;
			}
		}
		
	}// for k
	
	$('table.formattedTable').each(function() {
		setupPagination($(this));
	});
}


function getCellsNb(id,nrow)
/*====================================================
	- returns number of cells in a row
	- if nrow param is passed returns number of cells 
	of that specific row
=====================================================*/
{
  	var t = grabEBI(id);
	var tr;
	if(nrow == undefined) tr = grabTag(t,"tr")[0];
	else  tr = grabTag(t,"tr")[nrow];
	var n = getChildElms(tr);
	return n.childNodes.length;
}

function getRowsNb(id)
/*====================================================
	- returns total nb of filterable rows starting 
	from reference row if defined
=====================================================*/
{
	var t = grabEBI(id);
	var s = t.tf_ref_row;
	var ntrs = grabTag(t,"tr").length;
	return parseInt(ntrs-s);
}

function getChildElms(n)
/*====================================================
	- checks passed node is a ELEMENT_NODE nodeType=1
	- removes TEXT_NODE nodeType=3  
=====================================================*/
{
	if(n.nodeType == 1)
	{
		var enfants = n.childNodes;
		for(var i=0; i<enfants.length; i++)
		{
			var child = enfants[i];
			if(child.nodeType == 3) n.removeChild(child);
		}
		return n;	
	}
}

function getCellText(n)
/*====================================================
	- returns text + text of child nodes of a cell
=====================================================*/
{
	var s = "";
	var enfants = n.childNodes;
	for(var i=0; i<enfants.length; i++)
	{
		var child = enfants[i];
		if(child.nodeType == 3) s+= child.data;
		else s+= getCellText(child);
	}
	return s;
}

function grabEBI(id)
/*====================================================
	- this is just a getElementById shortcut
=====================================================*/
{
	return document.getElementById( id );
}

function grabTag(obj,tagname)
/*====================================================
	- this is just a getElementsByTagName shortcut
=====================================================*/
{
	return obj.getElementsByTagName( tagname );
}

function regexpEscape(s)
/*====================================================
	- escapes special characters [\^$.|?*+() 
	for regexp
	- Many thanks to Cedric Wartel for this fn
=====================================================*/
{
	// traite les caractères spéciaux [\^$.|?*+()
	//remplace le carctère c par \c
	function escape(e)
	{
		a = new RegExp('\\'+e,'g');
		s = s.replace(a,'\\'+e);
	}

	chars = new Array('\\','[','^','$','.','|','?','*','+','(',')');
	//chars.each(escape); // no prototype framework here...
	for(e in chars) escape(chars[e]);
	return s;
}

