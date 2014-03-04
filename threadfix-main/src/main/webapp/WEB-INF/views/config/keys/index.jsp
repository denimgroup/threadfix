<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>API Keys</title>
	<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/api-keys-controller.js"></script>
</head>

<body>
    <spring:url value="" var="emptyUrl"/>
    <div ng-controller="ApiKeysController" ng-init="csrfToken = '<c:out value="${ emptyUrl }"/>'">
        <h2>API Keys</h2>

        <%@include file="newForm.jsp" %>
        <%@include file="editForm.jsp" %>

        <div id="helpText">
            ThreadFix API Keys are used to access the REST interface.<br/>
        </div>

        <button class="btn" ng-click="openNewModal()">Create New Key</button>

        <div ng-show="loading" style="float:right" class="modal-loading"><div><span class="spinner dark"></span>Loading...</div></div>

        <table ng-hide="loading" class="table table-striped" style="table-layout:fixed;">
            <thead>
                <tr>
                    <th class="long first">Key</th>
                    <th class="medium">Note</th>
                    <th class="short centered">Edit / Delete</th>
                    <c:if test="${ not empty apiKeyList }">
                        <th class="short last">Restricted</th>
                    </c:if>
                </tr>
            </thead>
            <tbody>
                <tr ng-hide="keys || loading">
                    <td colspan="4">No API Keys found.</td>
                </tr>
                <tr ng-repeat="key in keys">
                    <td id="key{{ $index }}" style="max-width:300px;word-wrap: break-word;">{{ key.apiKey }}</td>
                    <td id="note{{ $index }}" style="max-width:300px;word-wrap: break-word;">{{ key.note }}</td>
                    <td class="centered" id="editKeyModal{{ $index }}">
                        <button class="btn" ng-click="openEditModal(key)">Edit / Delete</button>
                    </td>
                    <td id="restricted{{ $index }}">{{ key.isRestrictedKey }}</td>
                </tr>
            </tbody>
        </table>

    </div>
</body>
