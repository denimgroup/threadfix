<%@ include file="/common/taglibs.jsp"%>

<head>
  <title>Manage Users</title>
  <cbs:cachebustscript src="/scripts/user-modal-controller.js"/>
  <cbs:cachebustscript src="/scripts/user-page-controller.js"/>
</head>

<body id="config" ng-controller="UserPageController">

  <%@ include file="/WEB-INF/views/angular-init.jspf"%>

  <h2>Manage Users</h2>

  <div ng-show="successMessage" class="alert alert-success">
    <button class="close" ng-click="clearMessage()" type="button">&times;</button>
    {{ successMessage }}
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
