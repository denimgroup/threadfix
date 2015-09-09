var myAppModule = angular.module('threadfix');

myAppModule.controller('ManagePolicyModalController', function ($scope, $rootScope, $modalInstance, $http, threadFixModalService, tfEncoder, object, policys) {

    $scope.policys = policys;
    $scope.object = object;
    $scope.object.policysExpanded = true;

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.object.policys.sort(nameCompare);

    $scope.togglePolicys = function(object) {
        if (typeof $scope.object.policysExpanded === "undefined") {
            $scope.object.policysExpanded = false;
        }
        $scope.object.policysExpanded = !$scope.object.policysExpanded;
    };

    $scope.selectedPolicy = function(object, policy) {
        object.newPolicyId = policy.id;
    };

    $scope.addNewPolicy = function(acceptcriteria){
        if (!$scope.object.newPolicy) return;
        $scope.object.newPolicyError = null;
        $scope.object.newPolicyLoading = true;

        $http.get(tfEncoder.encode("/configuration/policies/" + acceptcriteria.id + "/add/" + $scope.object.id)).
            success(function(data, status, headers, config) {
                if (data.success) {
                    $scope.object.newPolicy = null;
                    threadFixModalService.addElement($scope.object.policys, data.object);

                    for (var i = 0; i < $scope.policys.length; i++ ) {
                        if (acceptcriteria.id == $scope.policys[i].id){
                            $scope.policys.splice(i,1);
                            break;
                        }
                    }

                    $scope.object.policys.sort(nameCompare);
                }
                else {
                    $scope.object.newPolicyError = data.message;
                }
                $scope.object.policysExpanded = true;
            }).
            error(function(data, status, headers, config) {
                $scope.error = "Failure. HTTP status was " + status;
            });
        $scope.object.newPolicyLoading = false;
    };

    $scope.deletePolicy = function(policy){
        if (confirm("Delete this Policy?")) {
            $http.get(tfEncoder.encode("/configuration/policies/" + policy.id + "/remove/" + $scope.object.id)).
                success(function(data, status, headers, config) {
                    if (data.success) {
                        threadFixModalService.deleteElement($scope.object.policys, policy);
                        threadFixModalService.addElement($scope.policys, policy);
                        $scope.policys.sort(nameCompare);
                    }
                    else {
                        $scope.errorMessage = "Failure. Message was : " + data.message;
                    }
                }).
                error(function(data, status, headers, config) {
                    $scope.error = "Failure. HTTP status was " + status;
                });
        }
    };

    $scope.focusInput = true;

    $scope.cancel = function () {
        $modalInstance.close({
            assignedPolicys: $scope.object.policys,
            availablePolicys: $scope.policys
        });
    };
});