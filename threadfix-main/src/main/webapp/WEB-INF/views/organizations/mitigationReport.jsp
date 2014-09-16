<%@ include file="/common/taglibs.jsp"%>
<h4>Mitigation Progress</h4>
<script type="text/javascript" src="<%=request.getContextPath()%>/scripts/graph-config-modal-controller.js"></script>
<div id="mitRep" style="float:left">
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/mitigation-progress-report.js"></script>
    <script type="text/javascript" src="<%=request.getContextPath()%>/scripts/d3.min.js"></script>
</div>
<div style="text-align: left; margin-left: 500px;">
    <table ng-repeat="s in activeResults">
        <tr>
            <td ng-if="s.name" style="font-size:14px">
                </br> Scanner:  {{s.name}}
            </td>
        </tr>
        <tr>
            <td ng-if="isNotNull(s.critical)">
                {{s.critical | number:2}}% mitigated towards critical goal
            </td>
        </tr>
        <tr>
            <td ng-if="isNotNull(s.high)">
                {{s.high | number:2}}% mitigated towards high goal
            </td>
        </tr>
        <tr>
            <td ng-if="isNotNull(s.medium)">
                {{s.medium | number:2}}% mitigated towards medium goal
            </td>
        </tr>
        <tr>
            <td ng-if="isNotNull(s.low)">
                {{s.low | number:2}}% mitigated towards low goal
            </td>
        </tr>
        <tr>
            <td ng-if="isNotNull(s.info)">
                {{s.info | number:2}}% mitigated towards info goal
            </td>
        </tr>
        <tr>
            <td ng-if="isNotNull(s.audit)">
                {{s.audit | number:2}}% mitigated towards audited goal
            </td>
        </tr>
    </table>
    </br>
    <table>
        <tr>
            <td>
                {{totalCount | number:2}}% completed towards application goal
            </td>
        </tr>
    </table>
</div>
<%@ include file="/WEB-INF/views/applications/forms/graphConfig.jsp"%>

   				 

             	
