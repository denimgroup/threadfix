<%@ include file="/common/taglibs.jsp"%>

<head>
  <title>Manage Filters</title>
  <cbs:cachebustscript src="/scripts/vulnerability-filters-controller.js"/>
  <cbs:cachebustscript src="/scripts/modal-controller-with-config.js"/>
  <cbs:cachebustscript src="/scripts/mappings-page-controller.js"/>
  <cbs:cachebustscript src="/scripts/scan-unmapped-finding-table-controller.js"/>
</head>

<body ng-controller="VulnerabilityFiltersController">

  <%@ include file="/WEB-INF/views/angular-init.jspf"%>

  <div ng-hide="initialized" class="spinner-div"><span class="spinner dark"></span>Loading</div><br>

  <h2>Scanner Type to CWE Mappings</h2>

  <%@ include file="/WEB-INF/views/mappings/channelVulnUpdate.jsp"%>

</body>
