<%@ include file="/common/taglibs.jsp"%>

<head>
    <title>Batch Tagging</title>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/batch-tagging-controller.js"></script>
</head>

<body id="tags" ng-controller="BatchTaggingController" ng-init="tagIds = '<c:out value="${tagIds}"/>'">

<ul class="breadcrumb">
    <li><a href="<spring:url value="/configuration/tags"/>">Back to Tags Page</a> <span class="divider">/</span></li>
</ul>
<h2>Batch Tagging</h2>

<%@ include file="/WEB-INF/views/successMessage.jspf" %>
<%@ include file="/WEB-INF/views/errorMessage.jspf" %>
<%@ include file="/WEB-INF/views/angular-init.jspf"%>

<div ng-hide="initialized" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

<div ng-show="initialized">
    <table ng-show="initialized">
        <tbody id="tagTableBody">
        <tr class="bodyRow">
            <td id="appName{{ tag.name }}">
                Application
            </td>
            <td>
                <input id="applicationNameTypeahead"
                       typeahead="application as (application.team.name + ' / ' + application.name) for application in applications | filter:$viewValue | limitTo:10"
                       type="text"
                       ng-model="newApplication"
                       placeholder="Enter Application Name"
                       typeahead-on-select="addNew(selectedApplications, newApplication); newApplication = '';"/>
            </td>
        </tr>
        <tr>
            <td>Tag</td>
            <td>
                <input id="tagNameTypeahead"
                       typeahead="tag as tag.name for tag in tags | filter:$viewValue | limitTo:10"
                       type="text"
                       ng-model="newTag"
                       placeholder="Enter Tag Name"
                       typeahead-on-select="addNew(selectedTags, newTag); newTag = '';"/>
            </td>
        </tr>
        </tbody>
    </table>

</div>
<br/>
<div>
    <div>
        <h5>Selected Applications</h5>
        <div ng-show="selectedApplications.length === 0">No Applications Selected</div>
        <div ng-repeat="app in selectedApplications">
            <span id="removeApp{{ app.name }}" class="pointer icon icon-minus-sign" ng-click="remove(selectedApplications, $index)"></span>
            {{ app.team.name + ' / ' + app.name }}
        </div>
    </div>
    <div>
        <h5>Selected Tags</h5>
        <div ng-show="selectedTags.length === 0">No Tags Selected</div>
        <div ng-repeat="tag in selectedTags">
            <span id="removeTag{{ tag.name }}" class="pointer icon icon-minus-sign" ng-click="remove(selectedTags, $index)"></span>
            {{ tag.name }}
        </div>
    </div>
    <div>
        <button id="submitBtn"
                ng-hide="submitting"
                class="btn btn-primary"
                ng-disabled="selectedApplications.length === 0 || selectedTags.length === 0"
                ng-click="submitBatchTag()">
            Submit
        </button>
        <button id="submittingBtn"
                ng-show="submitting"
                disabled="disabled"
                class="btn btn-primary">
            <span class="spinner"></span>
            Submitting
        </button>
    </div>
</div>


</body>
