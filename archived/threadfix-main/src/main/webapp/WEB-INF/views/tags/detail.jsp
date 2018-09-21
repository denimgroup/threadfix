<%@ include file="/common/taglibs.jsp"%>

<head>
    <title>Tag Details</title>
    <cbs:cachebustscript src="/scripts/tag-detail-page-controller.js"/>
    <cbs:cachebustscript src="/scripts/vulnerability-comments-table-controller.js"/>
</head>

<body id="tagDetail" ng-controller="TagDetailPageController">

<%@ include file="/WEB-INF/views/angular-init.jspf"%>
<ul class="breadcrumb">
    <li><a href="<spring:url value="/configuration/tags"/>">Back to Tags Page</a> <span class="divider">/</span></li>
</ul>
<h2 ng-non-bindable>Tag <c:out value="${ tag.name }"/> </h2>

<div class="container-fluid">
    <div id="statisticsDiv" class="row-fluid">
        <div class="span4">
            <h4>Tag Statistics</h4>
            <table class="dataTable">
                <tbody>
                <tr ng-show="type === 'APPLICATION'">
                    <td>Number of Applications</td>
                    <td class="inputValue" id="numApps" ng-non-bindable>
                        <c:out value="${ numApps }"/>
                    </td>
                </tr>
                <tr ng-show="type === 'VULNERABILITY'">
                    <td>Number of Vulnerabilities</td>
                    <td class="inputValue" id="numVulns" ng-non-bindable>
                        <c:out value="${ numVulns }"/>
                    </td>
                </tr>
                <tr ng-show="type === 'COMMENT'">
                    <td>Number of Vulnerability Comments</td>
                    <td class="inputValue" id="numVulnComments" ng-non-bindable>
                        <c:out value="${ numVulnComments }"/>
                    </td>
                </tr>
                </tbody>
            </table>
        </div>
    </div>

    <div>
        <%@ include file="appTable.jsp" %>
        <%@ include file="vulnTable.jsp" %>
        <div ng-controller="VulnerabilityCommentsTableController" ng-show="type === 'COMMENT'">
            <h4 style="padding-top:10px">Tagged Vulnerability Comments</h4>
            <%@ include file="commentTable.jsp" %>
        </div>
    </div>
</div>
</body>
