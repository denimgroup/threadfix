<%@ include file="/common/taglibs.jsp"%>

<head>
    <title>Custom CWE Text</title>
    <cbs:cachebustscript src="/scripts/custom-cwe-text-controller.js"/>
    <cbs:cachebustscript src="/scripts/modal-controller-with-config.js"/>
</head>

<body>
    <%@ include file="/WEB-INF/views/angular-init.jspf"%>
    <div ng-controller="CustomCweTextController">
        <h2>Custom CWE Text</h2>

        <%@ include file="/WEB-INF/views/successMessage.jspf" %>
        <%@ include file="/WEB-INF/views/errorMessage.jsp" %>
        <%@ include file="form.jsp" %>

        <div id="helpText">
            Custom CWE Test can be used to add additional text to a defect tracker defect.
        </div>

        <button class="btn" ng-click="openNewModal()" id="createNewCustomCweTextModalButton">Set Custom Text</button>

        <div ng-show="loading" style="float:right" class="modal-loading"><div><span class="spinner dark"></span>Loading...</div></div>

        <table id="table" ng-hide="loading" class="table table-striped" style="table-layout: fixed;">
            <thead>
                <tr>
                    <th class="first">CWE</th>
                    <th class="medium">Text</th>
                    <th class="centered last">Edit / Delete</th>
                </tr>
            </thead>
            <tbody>
                <tr ng-hide="genericVulnerabilitiesWithCustomText.length || loading">
                    <td colspan="3" style="text-align:center;">No Custom CWE Text found.</td>
                </tr>
                <tr ng-repeat="genericVulnerability in genericVulnerabilitiesWithCustomText">
                    <td id="cwe{{genericVulnerability.id}}">CWE {{genericVulnerability.displayId}}: {{genericVulnerability.name}}</td>
                    <td id="customText{{genericVulnerability.id}}">{{genericVulnerability.customText}}</td>
                    <td class="centered">
                        <button class="btn" id="editKeyModal{{genericVulnerability.id}}" ng-click="openEditModal(genericVulnerability)">Edit / Delete</button>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>
</body>