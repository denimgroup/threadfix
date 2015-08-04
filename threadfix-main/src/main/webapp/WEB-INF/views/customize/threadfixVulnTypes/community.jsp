<%@ include file="/common/taglibs.jsp"%>

<head>
  <title>Manage Filters</title>
  <cbs:cachebustscript src="/scripts/vulnerability-filters-controller.js"/>
  <cbs:cachebustscript src="/scripts/modal-controller-with-config.js"/>
</head>

<body ng-controller="VulnerabilityFiltersController">

<%@ include file="/WEB-INF/views/angular-init.jspf"%>

<div ng-hide="initialized" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

<div ng-show="initialized">
  <%@ include file="/WEB-INF/views/filters/channelFilterForm.jsp"%>

  <div id="tabsDiv">

    <c:if test="${ isEnterprise}">
      <!-- Channel Vulnerability Filter section -->
      <div ng-show="originalType === 'Global' || type === 'Global'">
        <h3>{{ channelVulnFiltersTitle }}</h3>

        <div id="channelVulnFiltersSuccessMessage" ng-show="channelVulnSuccessMessage" class="alert alert-success">
          <button class="close" ng-click="channelVulnSuccessMessage = undefined" type="button">&times;</button>
          {{ channelVulnSuccessMessage }}
        </div>

        <a id="createNewChannelVulnModalButton" ng-click="showNewChannelVulnFilterModal()" class="btn">Create New Scanner Vulnerability Filter</a>

        <div id="tableChannelVulnDiv">
          <%@ include file="/WEB-INF/views/filters/channelVulnTable.jsp" %>
        </div>
      </div>
      <!-- End Channel Vulnerability Filter section -->
    </c:if>
    <h3>{{ severityFiltersTitle }}</h3>
  </div>
</div>
</body>
