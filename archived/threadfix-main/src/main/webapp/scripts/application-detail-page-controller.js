var myAppModule = angular.module('threadfix');

myAppModule.controller('ApplicationDetailPageController', function ($scope, $window, $rootScope, tfEncoder) {

    $scope.dragEnabled = true;
    $scope.tab = { vulnerabilities: true };

    // too many IE problems
    $scope.disableOverlay = !~navigator.userAgent.indexOf("ie");

    $scope.$on('dragOff', function() {
        $scope.dragEnabled = false;
    });

    $scope.$on('dragOn', function() {
        $scope.dragEnabled = true;
    });

    $scope.$on('downloadScanFail', function(event, errorMessage) {
        $scope.errorMessage = errorMessage;
    });

    $scope.onFileSelect = function($files) {
        if ($scope.dragEnabled) {
            $scope.$broadcast('fileDragged', $files);
        }
    };

    $scope.appId  = $window.location.pathname.match(/([0-9]+)$/)[0];
    $scope.teamId = $window.location.pathname.match(/([0-9]+)/)[0];
    $scope.currentUrl = "/organizations/" + $scope.teamId + "/applications/" + $scope.appId;


    $scope.$on('rootScopeInitialized', function() {
        $scope.reportQuery = "&appId=" + $scope.appId + "&orgId=" + $scope.teamId;
    });

    $scope.rightReportTitle = "Top 10 Vulnerabilities";

    $scope.goToTeam = function(application) {
        window.location.href = tfEncoder.encode("/organizations/" + application.team.id);
    };

    $scope.$on('numVulns', function(event, numVulns) {
        $scope.numVulns = numVulns;
    });

    $scope.$on('policyStatuses', function(event, policyStatuses) {
        $scope.policyStatuses = policyStatuses;
    });

    $scope.$on('successMessage', function(event, message) {
        $scope.successMessage = message;
    });

    $scope.goToTag = function(tag) {
        window.location.href = tfEncoder.encode("/configuration/tags/" + tag.id +"/view");
    };

    $scope.setTab = function(tab) {
        if (tab === 'Vulnerabilities') {
            $scope.tab = { vulnerabilities: true };
        } else if (tab === 'Scans') {
            $scope.tab = { scans: true };
        } else if (tab === 'Files') {
            $scope.tab = { files: true };
        } else if (tab === 'Unmapped Findings') {
            $scope.tab = { unmappedFindings: true };
        } else if (tab === 'Scan Agent Tasks') {
            $scope.tab = { scanAgentTasks: true };
        } else if (tab === 'Scheduled Scans') {
            $scope.tab = { scheduledScans: true };
        } else if (tab === 'Policy') {
            $scope.tab = { policy: true };
        }
    };

});