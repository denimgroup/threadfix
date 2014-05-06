var myAppModule = angular.module('threadfix')

myAppModule.controller('ScanAgentTasksTabController', function ($scope, $window, $modal, $http, $log, $rootScope, tfEncoder) {

    $scope.heading = 'Scan Agent Tasks';

    $scope.base = window.location.pathname;

    $scope.currentUrl = $scope.$parent.currentUrl;

    var addExtraZero = function(listOfScans) {
        listOfScans.forEach(function(scan) {
            if (scan.minute === '0' || scan.minute === 0) {
                scan.extraMinute = 0;
            }
        });
    }

    $scope.openNewScanAgentTaskModal = function() {
        var modalInstance = $modal.open({
            templateUrl: 'newScanAgentTask.html',
            controller: 'ModalControllerWithConfig',
            resolve: {
                url: function() {
                    return tfEncoder.encode("/configuration/scanqueue" + $scope.currentUrl + "/addScanQueueTask");
                },
                buttonText: function() {
                    return "Add Scan Queue Task";
                },
                object: function() {
                    return {
                        scanQueueType: 'OWASP Zed Attack Proxy'
                    };
                },
                config: function() {
                    return {
                        scanners: ['OWASP Zed Attack Proxy', 'Burp Suite', 'Acunetix WVS', 'IBM Rational AppScan']
                    }
                }
            }
        });

        modalInstance.result.then(function (scanAgentTasks) {
            $scope.scanAgentTasks = scanAgentTasks;
            addExtraZero($scope.scanAgentTasks);
            setHeader();
        }, function () {
            $log.info('Modal dismissed at: ' + new Date());

        });
    }

    var setHeader = function() {
        if (!$scope.scanAgentTasks || !$scope.scanAgentTasks.length > 0) {
            $scope.scanAgentTasks = undefined;
            $scope.heading = "0 Scan Agent Tasks";
        } else {
            if ($scope.scanAgentTasks.length === 1) {
                $scope.heading = '1 Scan Agent Task';
            } else {
                $scope.heading = $scope.scanAgentTasks.length + ' Scan Agent Tasks';
            }
        }
    }

    $scope.deleteScanAgentTask = function(task) {

        if (confirm('Are you sure you want to delete this scan queue task?')) {
            task.deleting = true;
            $http.post(tfEncoder.encode("/configuration/scanqueue" + $scope.currentUrl + "/scanQueueTask/" + task.id + "/delete")).
                success(function(data, status, headers, config) {

                    if (data.success) {
                        var index = $scope.scanAgentTasks.indexOf(task);

                        if (index > -1) {
                            $scope.scanAgentTasks.splice(index, 1);
                        }

                        setHeader();

                    } else {
                        task.deleting = false;
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

    $scope.goTo = function(task) {
        window.location.href = tfEncoder.encode("/configuration/scanqueue/" + task.id + "/detail");
    };

    $scope.$on('scanAgentTasks', function(event, scanAgentTasks) {
        $scope.scanAgentTasks = scanAgentTasks;
        addExtraZero($scope.scanAgentTasks);
        setHeader();
    });
});