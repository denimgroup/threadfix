<%@ include file="/common/taglibs.jsp"%>

<style type="text/css">
	.ui-widget-header {
		background: url("images/ui-bg_highlight-soft_75_cccccc_1x100.png") repeat-x scroll 50% 50% #38616D;
		color: #FFFFFF;
	}
	
	.ui-state-default, .ui-widget-content .ui-state-default, .ui-widget-header .ui-state-default {
		background:url("images/ui-bg_glass_75_e6e6e6_1x400.png") repeat-x scroll 50% 50% #38616D;
		border:1px solid #D3D3D3;
		color:#FFFFFF;
		font-weight:bold;
	}
	
	.ui-widget-content {
		background: #EFEFEF;
	}

</style>


<div id="delete-dialog" title="Delete" style="display:none">
	<p><span class="ui-icon ui-icon-alert" style="float:left; margin:0 7px 20px 0;"></span>Are you sure you want to delete this <span id="deleteType"></span>?</p>
</div>	