<tab ng-hide="numVulns" id='vulnTab' heading="<c:out value='${ numVulns }'/> Vulnerabilities">

    <%@ include file="../../vulnerabilities/vulnSearchControls.jsp" %>

</tab>

<tab ng-show="numVulns" id='vulnTab' heading="{{ numVulns }} Vulnerabilities">

    <%@ include file="../../vulnerabilities/vulnSearchControls.jsp" %>

</tab>
