<%@ include file="/common/taglibs.jsp"%>

<div id="footer">
<div id="poweredBy">ThreadFix is Powered by</div>
<div id="bottomLogo">
	<a href="http://www.denimgroup.com/" class="denim-group" target="_blank">
		<img src="<%=request.getContextPath()%>/images/dg_logo_white.png" class="transparent_png"
		alt="Denim Group" />
	</a>
</div>
<div id="copyright">
    Version 2.2-snapshot. Copyright &copy; 2009 - 2014. Denim Group, Ltd. All rights reserved. Built on
    <fmt:formatDate value="${requestScope.buildDate}"/>
</div>

</div>
