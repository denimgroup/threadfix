<%@ include file="/common/taglibs.jsp"%>

<head>
    <title>Tag Details</title>
    <cbs:cachebustscript src="/scripts/tag-detail-page-controller.js"/>
</head>

<body id="tagDetail" ng-controller="TagDetailPageController">

<%@ include file="/WEB-INF/views/angular-init.jspf"%>
<ul class="breadcrumb">
    <li><a href="<spring:url value="/configuration/tags"/>">Back to Tags Page</a> <span class="divider">/</span></li>
</ul>
<h2>Tag <c:out value="${ tag.name }"/> </h2>

<div class="container-fluid">
    <div id="statisticsDiv" class="row-fluid">
        <div class="span4">
            <h4>Tag Statistics</h4>
            <table class="dataTable">
                <tbody>
                <tr>
                    <td>Number of Applications</td>
                    <td class="inputValue" id="numApps">
                        <c:out value="${ numApps }"/>
                    </td>
                </tr>
                <tr>
                    <td>Number of Vulnerability Comments</td>
                    <td class="inputValue" id="numVulnComments">
                        <c:out value="${ numVulnComments }"/>
                    </td>
                </tr>
                </tbody>
            </table>
        </div>
    </div>

    <div>
        <%@ include file="appTable.jsp" %>
        <%@ include file="commentTable.jsp" %>
    </div>
</div>
</body>
