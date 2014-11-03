<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Tags</title>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/tags-page-controller.js"></script>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/modal-controller-with-config.js"></script>
</head>

<body id="tags" ng-controller="TagsPageController">

	<h2>Tags</h2>

    <%@ include file="/WEB-INF/views/successMessage.jspf" %>
    <%@ include file="/WEB-INF/views/errorMessage.jspf" %>
    <%@ include file="/WEB-INF/views/angular-init.jspf"%>
    <%@ include file="/WEB-INF/views/tags/createTagForm.jsp" %>
    <%@ include file="/WEB-INF/views/tags/editTagForm.jsp" %>

    <div ng-hide="initialized" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

    <a ng-show="initialized" id="createTagModalButton" ng-click="openNewModal()" class="btn">Create Tag</a>

    <table ng-show="initialized" class="table table-striped">
        <thead>
            <tr>
                <th class="long first">Name</th>
                <th class="centered last">Edit / Delete</th>
            </tr>
        </thead>
        <tbody id="tagTableBody">
            <tr ng-hide="tags" class="bodyRow">
                <td colspan="2" style="text-align:center;">No Tags found.</td>
            </tr>
            <tr ng-show="tags" ng-repeat="tag in tags" class="bodyRow">
                <td class="details pointer" id="tagName{{ tag.name }}">
                    <a ng-click="goToTag(tag)">{{ tag.name }}</a>
                </td>
                <td class="centered">
                    <a id="editTagModalButton{{ tag.name }}" ng-click="openEditModal(tag)" class="btn">Edit / Delete</a>
                </td>
            </tr>
        </tbody>
    </table>
</body>
