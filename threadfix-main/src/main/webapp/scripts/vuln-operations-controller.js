var module = angular.module('threadfix');

//essentially a copy of BulkOperationsController, copy and not factorized to avoid conflicts in the future
module.controller('VulnOperationsController', function($rootScope, $http, $log, $modal, tfEncoder, $scope) {

    var $parent = $scope.$parent;

    //changing way to get application
    var getApplication = function() {
        return $scope.vulnerability.app;
    };

    var getAppUrlBase = function () {
        var app = getApplication();
        return "/organizations/" + app.team.id + "/applications/" + app.id;
    };

    //Changing return value here
    var getFilteredVulns = function() {
        // here inserting the single vuln intead of the filtered list
        var filteredVulns = [$scope.vulnerability];

        return filteredVulns;
    };

    $scope.showSubmitGrcControlModal = function() {

        var filteredVulns = getFilteredVulns();

        if (filteredVulns.length === 0) {
            alert('You must select at least one vulnerability.');
            return;
        }

        filteredVulns = filteredVulns.filter(function(vuln) {
            return !vuln.grcControl;
        });

        if (filteredVulns.length === 0) {
            alert('All of the selected vulnerabilities already have controls.');
            return;
        }

        var modalInstance = $modal.open({
            templateUrl: 'submitGrcControlLoadingModal.html',
            controller: 'GRCControlSubmissionModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode(getAppUrlBase() + "/controls");
                },
                object: function () {
                    return {};
                },
                config: function() {
                    return {
                        vulns: filteredVulns
                    }
                }
            }
        });

        $scope.currentModal = modalInstance;

        modalInstance.result.then(function (s) {
            $scope.refresh();
            $rootScope.$broadcast('successMessage', s);
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.showSubmitDefectModal = function() {

        var filteredVulns = getFilteredVulns();

        if (filteredVulns.length === 0) {
            alert('You must select at least one vulnerability.');
            return;
        }

        filteredVulns = filteredVulns.filter(function(vuln) {
            return !vuln.defect;
        });

        if (filteredVulns.length === 0) {
            alert('All of the selected vulnerabilities already have defects.');
            return;
        }

        var modalInstance = $modal.open({
            windowClass: 'submit-defect-form',
            templateUrl: 'submitDefectForm.html',
            controller: 'DefectSubmissionModalController',
            resolve: {
                url: function() {
                    return tfEncoder.encode(getAppUrlBase() + "/defects");
                },
                configUrl: function() {
                    return tfEncoder.encode(getAppUrlBase() + "/defectSubmission");
                },
                object: function () {
                    return {};
                },
                config: function() {
                    return {
                        vulns: filteredVulns,
                        typeName: getApplication().defectTracker.defectTrackerType.name
                    }
                },
                defectDefaultsConfig: function() {
                    return {
                        defectTrackerId : getApplication().defectTracker.id,
                        mainDefaultProfile : getApplication().mainDefaultDefectProfile // may be null
                    };
                }
            }
        });

        $scope.currentModal = modalInstance;

        modalInstance.result.then(function (s) {
            $scope.refresh();
            $rootScope.$broadcast('successMessage', "Successfully submitted the defect: " + s);
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    $scope.showMergeDefectModal = function() {

        var filteredVulns = getFilteredVulns();

        if (filteredVulns.length === 0) {
            alert('You must select at least one vulnerability.');
            return;
        }

        filteredVulns = filteredVulns.filter(function(vuln) {
            return !vuln.defect;
        });

        if (filteredVulns.length === 0) {
            alert('All of the selected vulnerabilities already have defects.');
            return;
        }

        var modalInstance = $modal.open({
            windowClass: 'submit-defect-form',
            templateUrl: 'addToExistingDefect.html',
            controller: 'AddToExistingDefectController',
            resolve: {
                url: function() {
                    return tfEncoder.encode(getAppUrlBase() + "/defects/merge");
                },
                configUrl: function() {
                    return tfEncoder.encode(getAppUrlBase() + "/defectSubmissionWithIssues");
                },
                object: function () {
                    return {};
                },
                config: function() {
                    return {
                        vulns: filteredVulns
                    }
                }
            }
        });

        $scope.currentModal = modalInstance;

        modalInstance.result.then(function (returnValue) {

            $scope.refresh();
            $rootScope.$broadcast('successMessage', returnValue);
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());
        });
    };

    //Cropping the end that is not necessary for the single vuln
});