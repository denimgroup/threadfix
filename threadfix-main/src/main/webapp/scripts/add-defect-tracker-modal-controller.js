var myAppModule = angular.module('threadfix')

myAppModule.controller('AddDefectTrackerModalController', function ($scope, $http, $rootScope, $modalInstance, tfEncoder, threadFixModalService, object, config, timeoutService) {

    $scope.object = object;

    $scope.config = config;

    $scope.loading = false;

    $scope.getProductNames = function() {
        $scope.loading = true;

        var app = $scope.config.application;
        var url = tfEncoder.encode("/organizations/" + app.team.id + "/applications/jsontest");

        timeoutService.timeout();

        $http.post(url, $scope.object).
            success(function(data, status, headers, config) {
                timeoutService.cancel();
                $scope.loading = false;

                if (data.success) {
                    $scope.productNames = data.object;
                    $scope.error = null;
                } else {
                    $scope.error = "Failure. Message was : " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                timeoutService.cancel();
                $scope.loading = false;
                $scope.error = "Failure. " + (data && data.message ? "Message was " + data.message : "") + ". HTTP status was " + status;
            });
    };

    $scope.ok = function (valid) {

        if (valid) {
            timeoutService.timeout();
            $scope.loading = true;

            var app = $scope.config.application;
            var url = tfEncoder.encode("/organizations/" + app.team.id + "/applications/" + app.id + "/edit/addDTAjax");

            $scope.object.defectTracker = {
                id: $scope.object.defectTrackerId
            };

            $scope.object.name = app.name;
            $scope.object.organization = { id: app.team.id };

            threadFixModalService.post(url, $scope.object).
                success(function(data, status, headers, config) {
                    timeoutService.cancel();
                    $scope.loading = false;

                    if (data.success) {
                        $modalInstance.close(data.object);
                    } else {
                        if (data.errorMap) {
                            for (var index in data.errorMap) {
                                if (data.errorMap.hasOwnProperty(index)) {

                                    if (data.errorMap[index] === 'errors.self.certificate') {
                                        $scope.showKeytoolLink = true;
                                    } else {
                                        $scope.object[index + "_error"] = data.errorMap[index];
                                    }
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
                    $scope.error = "Failure. " + (data && data.message ? "Message was " + data.message : "") + ". HTTP status was " + status;
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

    $scope.toggleUseDefaultCredentials = function(){

        if($scope.object.useDefaultCredentials){

            angular.forEach($scope.config.defectTrackerList, function(value, key){
                if(value.id === parseInt($scope.object.defectTrackerId)){
                    $scope.object.userName = value.defaultUsername;
                }
            });

            $scope.object.password = "*****";
        }else{
            $scope.object.userName = "";
            $scope.object.password = "";
            $scope.productNames = null;
            $scope.object.projectName = null;
        }
    };

    $scope.toggleUseDefaultProduct = function(){

        if($scope.object.useDefaultProduct){

            angular.forEach($scope.config.defectTrackerList, function(value, key){
                if(value.id === parseInt($scope.object.defectTrackerId)){
                    $scope.productNames = [value.defaultProductName];
                    $scope.object.projectName = $scope.productNames[0];
                }
            });
        }else{
            $scope.productNames = null;
            $scope.object.projectName = null;
        }
    };

    $scope.updateDefaultCredentialsAndProduct = function(){
        $scope.toggleUseDefaultCredentials();
        $scope.toggleUseDefaultProduct();
    }
});
