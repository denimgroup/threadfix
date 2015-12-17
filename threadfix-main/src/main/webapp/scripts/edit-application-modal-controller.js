    var myAppModule = angular.module('threadfix');


// this is a shim for optional dependencies
myAppModule.value('deleteUrl', null);

// TODO wrap this back into genericModalController and make config optional

myAppModule.controller('EditApplicationModalController', function ($log, $scope, $rootScope, $modalInstance, $http, $window, threadFixModalService, object, config, url, buttonText, deleteUrl, timeoutService, tfEncoder, tagsUrl) {

    $scope.object = object;

    $scope.config = config;

    $scope.buttonText = buttonText;

    $scope.loading = false;

    $scope.ok = function (valid) {

        if (valid) {
            timeoutService.timeout();
            $scope.loading = true;

            // updating application tags list
            var jsonStr = JSON.stringify($scope.object.tags);
            var map = {
                jsonStr: jsonStr
            };
            threadFixModalService.post(tagsUrl, map).
                success(function(outerData, status, headers, config) {
                    $scope.loading = false;

                    if (outerData.success) {
                        threadFixModalService.post(url, $scope.object).
                            success(function(data, status, headers, config) {
                                timeoutService.cancel();
                                $scope.loading = false;

                                if (data.success) {
                                    data.object.tags = outerData.object;
                                    $modalInstance.close(data.object);
                                } else {
                                    if (data.errorMap) {
                                        for (var index in data.errorMap) {
                                            if (data.errorMap.hasOwnProperty(index)) {
                                                $scope.object[index + "_error"] = data.errorMap[index];
                                            }
                                        }
                                    } else {
                                        $scope.error = "Failure. Message was : " + data.message;
                                    }
                                }
                            }).
                            error(function(data, status, headers, config) {
                                timeoutService.cancel();
                                $scope.loading = false;
                                $scope.error = "Failure. HTTP status was " + status;
                            });
                    } else {
                        if (data.errorMap) {
                            for (var index in data.errorMap) {
                                if (data.errorMap.hasOwnProperty(index)) {

                                    $scope.object[index + "_error"] = data.errorMap[index];
                                }
                            }
                        } else {
                            $scope.error = "Failure. Message was : " + data.message;
                        }
                    }
                }).
                error(function(data, status, headers, config) {
                    $scope.loading = false;
                    $scope.error = "Failure. HTTP status was " + status;
                });
        }
    };

    $scope.focusInput = true;

    $scope.switchTo = function(name) {
        $rootScope.$broadcast('modalSwitch', name);
    };

    $scope.cancel = function () {
        timeoutService.cancel();
        $modalInstance.dismiss('cancel');
    };

    $scope.showDeleteDialog = function(itemName) {
        if (confirm("Are you sure you want to delete this " + itemName + "?")) {
            $http.post(deleteUrl).
                success(function(data, status, headers, config) {
                    $modalInstance.close(false);
                }).
                error(function(data, status, headers, config) {
                    $scope.error = "Failure. HTTP status was " + status;
                });
        }
    };

    $scope.goToPolicyPage = function() {
        $window.location.href = tfEncoder.encode("/configuration/policies");
    };

    $scope.removeDefectTracker = function(){
        if(confirm("Are you sure you want to remove the defect tracker?")){
            var app = $scope.config.application;
            var url = tfEncoder.encode("/organizations/" + app.team.id + "/applications/" + app.id + "/edit/removeDTAjax");
            $http.post(url).
            success(function(data, status, headers, config) {
                $scope.config.application.defectTracker = data.defectTracker;
                $modalInstance.dismiss('cancel');
                $scope.switchTo('appEdit');
            }).
            error(function(data, status, headers, config) {
                $scope.error = "Failure. HTTP status was " + status;
            });
        }
    };

});
