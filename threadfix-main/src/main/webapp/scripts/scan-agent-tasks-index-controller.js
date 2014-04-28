var myAppModule = angular.module('threadfix')

myAppModule.controller('ScanAgentTasksIndexController', function ($scope, $window, $modal, $http, $log, $rootScope, tfEncoder) {

    $scope.$on('rootScopeInitialized', function() {
        $http.get(tfEncoder.encode('/configuration/scanqueue/list')).
            success(function(data, status, headers, config) {

                if (data.success) {

                    if (data.object.length > 0) {
                        $scope.scanAgentTasks = data.object;
                    }

                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }

                $scope.initialized = true;
            }).
            error(function(data, status, headers, config) {
                $scope.initialized = true;
                $scope.errorMessage = "Failed to retrieve waf list. HTTP status was " + status;
            });
    });

    $scope.deleteScanAgentTask = function(task) {

        if (confirm('Are you sure you want to delete this scan queue task?')) {
            task.deleting = true;
            $http.post(tfEncoder.encode("/configuration/scanqueue/scanQueueTask/" + task.id + "/delete")).
                success(function(data, status, headers, config) {

                    if (data.success) {
                        var index = $scope.scanAgentTasks.indexOf(task);

                        if (index > -1) {
                            $scope.scanAgentTasks.splice(index, 1);
                        }

                        if ($scope.scanAgentTasks.length == 0) {
                            $scope.scanAgentTasks = undefined;
                        }

                        $scope.successMessage = data.object;

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

});