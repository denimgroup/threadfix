<div ng-show="vulnerability.dynamicFindings.length > 1">
    <h4>Request Variants</h4>
    <div ng-repeat="finding in vulnerability.dynamicFindings">
        <a class="pointer" ng-click="toggleFinding(finding)">
            Toggle {{ finding.scannerName }} ({{ $index + 1 }}) request
        </a>
        <br />

        <div id='{{ finding.id }}' ng-show="isShowFlow{{finding.id}}">
            <h5>
                {{ finding.scannerName }} ({{ $index + 1 }})
            </h5>
            <table class="dataTable">
                <tr>
                    <td class="bold" valign=top>Attack Request</td>
                    <td class="inputValue" style="word-wrap: break-word;"><PRE id="attackRequest">{{ finding.attackRequest }}</PRE></td>
                </tr>
                <tr>
                    <td class="bold" valign=top>Attack Response</td>
                    <td class="inputValue" style="word-wrap: break-word;"><PRE id="attackResponse">{{ finding.attackResponse }}</PRE></td>
                </tr>
            </table>
        </div>
    </div>
</div>

<div ng-show="vulnerability.dynamicFindings.length === 1">
    <h4>Request</h4>
    <table class="dataTable">
        <tr>
            <td class="bold" valign=top>Attack Request</td>
            <td class="inputValue" style="word-wrap: break-word;"><PRE id="singleAttackRequest">{{ vulnerability.dynamicFindings[0].attackRequest }}</PRE></td>
        </tr>
        <tr>
            <td class="bold" valign=top>Attack Response</td>
            <td class="inputValue" style="word-wrap: break-word;"><PRE id="singleAttackResponse">{{ vulnerability.dynamicFindings[0].attackResponse }}</PRE></td>
        </tr>
    </table>
</div>