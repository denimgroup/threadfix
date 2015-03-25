<%@ include file="/common/taglibs.jsp"%>

<head>
	<title>Download Tools</title>
</head>
<body>
    <%@ include file="/WEB-INF/views/angular-init.jspf"%>
    <%@ include file="/WEB-INF/views/successMessage.jspf" %>
    <%@ include file="/WEB-INF/views/errorMessage.jsp" %>

    <div id="helpText">
        Tools download page.<br/>
    </div>

    <div ng-show="loading" style="float:right" class="modal-loading"><div><span class="spinner dark"></span>Loading...</div></div>

    <div class="container">
        <h2>Tools Download</h2>
        <table class="table">
            <thead>
                <tr>
                    <th class="medium first">Tool</th>
                    <th class="short">Documentation</th>
                    <th class="short last">Download</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>ThreadFix Command Line Interface (CLI)</td>
                    <td><a target="_blank" href="https://github.com/denimgroup/threadfix/wiki/Command-Line-Interface">
                        Wiki</a></td>
                    <td><a href="<spring:url value="/configuration/download/tfcli" htmlEscape="true"/>">
                        Jar File</a></td>
                </tr>
                <tr>
                    <td>ThreadFix Scan Importer CLI</td>
                    <td><a target="_blank" href="https://github.com/denimgroup/threadfix/wiki/CLI-Importers">
                        Wiki</a></td>
                    <td><a href="<spring:url value="/configuration/download/tfscancli" htmlEscape="true"/>">
                        Jar File</a></td>
                </tr>
                <tr>
                    <td>Endpoint Command Line Interface</td>
                    <td><a target="_blank" href="https://github.com/denimgroup/threadfix/wiki/Endpoint-CLI">
                        Wiki
                    </a></td>
                    <td><a href="<spring:url value="/configuration/download/tfendpoint" htmlEscape="true"/>">
                        Jar File</a></td>
                </tr>
                <tr>
                    <td>ThreadFix Data Migration</td>
                    <td><a target="_blank" href="https://github.com/denimgroup/threadfix/wiki/Data-Migration-Tool">
                        Wiki
                    </a></td>
                    <td><a href="<spring:url value="/configuration/download/tfdatamigration" htmlEscape="true"/>">
                        Jar File</a></td>
                </tr>
                <tr>
                    <td>Burp Plugin</td>
                    <td><a target="_blank" href="https://github.com/denimgroup/threadfix/wiki/Burp-Plugin">
                        Wiki
                    </a></td>
                    <td><a href="<spring:url value="/configuration/download/burp" htmlEscape="true"/>">
                        Jar File</a></td>
                </tr>
                <tr>
                    <td>ZAP Plugin</td>
                    <td><a target="_blank" href="https://github.com/denimgroup/threadfix/wiki/Zap-Plugin">
                        Wiki
                    </a></td>
                    <td><a href="<spring:url value="/configuration/download/zap" htmlEscape="true"/>">
                        Zap File</a></td>
                </tr>
                <tr>
                    <td>Sonar Plugin</td>
                    <td><a target="_blank" href="https://github.com/denimgroup/threadfix/wiki/Using-the-Sonar-Plugin">
                        Wiki
                    </a></td>
                    <td><a href="<spring:url value="/configuration/download/sonar" htmlEscape="true"/>">
                        Jar File</a></td>
                </tr>
                <tr>
                    <td>SSVLConverter</td>
                    <td><a target="_blank" href="https://github.com/denimgroup/threadfix/wiki/SSVLConverter">
                        Wiki
                        </a></td>
                    <td><a href="<spring:url value="/configuration/download/ssvl-converter" htmlEscape="true"/>">
                        Jar File</a></td>
                </tr>
            </tbody>
        </table>
    </div>

</body>
