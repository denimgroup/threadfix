<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<%@ include file="/common/taglibs.jsp"%>

<html lang="en">
    <head>
        <%@ include file="/common/meta.jsp" %>
        <title><decorator:title/> | <spring:message code="webapp.name"/></title>

        <link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/styles/reset-fonts-grids.css"/>
        <link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/styles/bootstrap.min.css"/>
        <link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/styles/main.css"/>
        <link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/styles/jquery-ui.css"/>
        <link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/styles/d3.css"/>
        <link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/styles/angular-multi-select.css"/>

        <cbs:cachebustscript src="/scripts/angular-file-upload-shim.min.js"/>

        <cbs:cachebustscript src="/scripts/angular.min.js"/>
        <cbs:cachebustscript src="/scripts/ui-bootstrap-tpls-0.10.0.min.js"/>

        <cbs:cachebustscript src="/scripts/angular-file-upload.min.js"/>
        <cbs:cachebustscript src="/scripts/dynamic-forms.js"/>

        <cbs:cachebustscript src="/scripts/filters.js"/>
        <cbs:cachebustscript src="/scripts/threadfix-module.js"/>
        <cbs:cachebustscript src="/scripts/services.js"/>
        <cbs:cachebustscript src="/scripts/generic-modal-controller.js"/>
        <cbs:cachebustscript src="/scripts/header-controller.js"/>
        <cbs:cachebustscript src="/scripts/wrapper-controller.js"/>
        <cbs:cachebustscript src="/scripts/init-controller.js"/>
        <cbs:cachebustscript src="/scripts/directives.js"/>
        <cbs:cachebustscript src="/scripts/angular-multi-select.js"/>

        <cbs:cachebustscript src="/scripts/report/directives/d3-dashboards.js"/>
        <cbs:cachebustscript src="/scripts/report/directives/d3-trending-scans.js"/>
        <cbs:cachebustscript src="/scripts/report/d3.js"/>
        <cbs:cachebustscript src="/scripts/report/d3-donut.js"/>
        <cbs:cachebustscript src="/scripts/report/report-services.js"/>

        <!--[if lt IE 7]>
            <link rel="stylesheet" type="text/css" href="<%=request.getContextPath()%>/styles/ie6.css"/>
            <cbs:cachebustscript src="/scripts/iepngfix_tilebg.js"/>
        <![endif]-->

        <decorator:head/>
    </head>

    <body ng-app='threadfix'
          <decorator:getProperty property="body.id" writeEntireProperty="true"/>
          <decorator:getProperty property="body.ng-controller" writeEntireProperty="true"/>
          <decorator:getProperty property="body.ng-init" writeEntireProperty="true"/>
          <decorator:getProperty property="body.ng-class" writeEntireProperty="true"/>
          <decorator:getProperty property="body.class" writeEntireProperty="true"/>
          <decorator:getProperty property="body.ng-file-drop" writeEntireProperty="true"/>>

        <spring:url value="" var="emptyUrl" htmlEscape="true"/>
        <div id="wrapper">
            <div id="main">
                <jsp:include page="/common/header.jsp"/>
                <div class="top-corners corners">
                    <div class="left corner"><!-- --></div>
                    <div class="right corner"><!-- --></div>
                    <div class="center"><!-- --></div>
                </div>
                <div id="main-content" ng-controller="WrapperController" class="hide-wrapper" ng-class="{ 'cancel-hide-wrapper': loaded }">
                    {{name}}
                    <decorator:body/>
                    <div ng-hide="loaded" class="modal-loading"><div><span class="spinner dark"></span>Loading...</div></div>
                </div>
                <div class="bottom-corners corners">
                    <div class="left corner"><!-- --></div>
                    <div class="right corner"><!-- --></div>
                    <div class="center"><!-- --></div>
                </div>
            </div>
        </div>
        <jsp:include page="/common/footer.jsp"/>
        <jsp:include page="/common/delete.jsp"/>
    </body>
</html>
