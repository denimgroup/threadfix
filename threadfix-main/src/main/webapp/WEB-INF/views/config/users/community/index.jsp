<%@ include file="/common/taglibs.jsp"%>

<head>
  <title>Manage Users</title>
  <cbs:cachebustscript src="/scripts/user-modal-controller.js"/>
  <cbs:cachebustscript src="/scripts/user-page-controller.js"/>
  <security:authorize ifAllGranted="ROLE_ENTERPRISE">
    <cbs:cachebustscript src="/scripts/history-table-controller.js"/>
  </security:authorize>
</head>

<body id="config" ng-controller="UserPageController">

  <%@ include file="/WEB-INF/views/angular-init.jspf"%>

  <h2>Manage Users</h2>

  <div ng-show="usersSuccessMessage" id="usersSuccessMessage" class="alert alert-success">
    <button class="close" ng-click="usersSuccessMessage = undefined" type="button">&times;</button>
    {{ usersSuccessMessage }}
  </div>
  <%@ include file="/WEB-INF/views/errorMessage.jsp" %>

  <div class="row">
    <div class="span3">
      <%@ include file="../common/userList.jspf" %>
    </div>
    <div class="span8">
      <%@ include file="../common/userDetails.jspf" %>
    </div>
  </div>
</body>
