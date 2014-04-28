var myAppModule = angular.module('threadfix')

myAppModule.controller('ScheduledScanTabController', function ($scope, $window, $modal, $http, $log, $rootScope, tfEncoder) {

    $scope.heading = 'Scheduled Scans';

    $scope.base = window.location.pathname;

    $scope.currentUrl = $scope.$parent.currentUrl;

    var addExtraZero = function(listOfScans) {
        listOfScans.forEach(function(scan) {
            if (scan.minute === '0' || scan.minute === 0) {
                scan.extraMinute = 0;
            }
        });
    }

    $scope.openNewScheduledScanModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'newScheduledScan.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode($scope.currentUrl + "/scheduledScans/addScheduledScan");
                },
                buttonText: function() {
                    return "Add Scheduled Scan";
                },
                object: function() {
                    return {
                        frequency: 'Daily',
                        hour: '6',
                        minute: '0',
                        period: 'AM',
                        scanner: 'OWASP Zed Attack Proxy',
                        day: 'Sunday'
                    };
                },
                config: function() {
                    return {
                        scanners: ['OWASP Zed Attack Proxy', 'Burp Suite', 'Acunetix WVS', 'IBM Rational AppScan']
                    }
                }
            }
        });

        modalInstance.result.then(function (scheduledScans) {
            $scope.scheduledScans = scheduledScans;
            addExtraZero($scope.scheduledScans);
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());

        });
    }

    var setHeader = function() {
        if (!$scope.scheduledScans || !$scope.scheduledScans.length > 0) {
            $scope.scheduledScans = undefined;
            $scope.heading = "0 Scheduled Scans";
        } else {
            if ($scope.scheduledScans.length === 1) {
                $scope.heading = '1 Scheduled Scan';
            } else {
                $scope.heading = $scope.scheduledScans.length + ' Scheduled Scans';
            }
        }
    }

    $scope.deleteScheduledScan = function(scan) {

        if (confirm('Are you sure you want to delete this scheduled scan?')) {
            scan.deleting = true;
            $http.post(tfEncoder.encode($scope.currentUrl + "/scheduledScans/scheduledScan/" + scan.id + "/delete")).
                success(function(data, status, headers, config) {

                    if (data.success) {
                        var index = $scope.scheduledScans.indexOf(scan);

                        if (index > -1) {
                            $scope.scheduledScans.splice(index, 1);
                        }

                        setHeader();
                        $scope.$parent.successMessage = "Successfully deleted document " + document.name;

                    } else {
                        scan.deleting = false;
                        $scope.errorMessage = "Something went wrong. " + data.message;
                    }
                }).
                error(function(data, status, headers, config) {
                    $log.info("HTTP request for form objects failed.");
                    // TODO improve error handling and pass something back to the users
                    document.deleting = false;
                    $scope.errorMessage = "Request to server failed. Got " + status + " response code.";
                });
        }
    };

    $scope.$on('scheduledScans', function(event, scheduledScans) {
        $scope.scheduledScans = scheduledScans;
        addExtraZero($scope.scheduledScans);
        setHeader();
    });
});