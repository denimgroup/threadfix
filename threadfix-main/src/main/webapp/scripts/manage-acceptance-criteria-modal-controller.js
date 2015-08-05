var myAppModule = angular.module('threadfix');

myAppModule.controller('ManageAcceptanceCriteriaModalController', function ($scope, $rootScope, $modalInstance, $http, threadFixModalService, tfEncoder, object, acceptanceCriterias) {

    $scope.acceptanceCriterias = acceptanceCriterias;
    $scope.object = object;
    $scope.object.acceptanceCriteriasExpanded = true;

    var nameCompare = function(a,b) {
        return a.name.localeCompare(b.name);
    };

    $scope.object.acceptanceCriterias.sort(nameCompare);

    $scope.toggleAcceptanceCriterias = function(object) {
        if (typeof $scope.object.acceptanceCriteriasExpanded === "undefined") {
            $scope.object.acceptanceCriteriasExpanded = false;
        }
        $scope.object.acceptanceCriteriasExpanded = !$scope.object.acceptanceCriteriasExpanded;
    };

    $scope.selectedAcceptanceCriteria = function(object, acceptanceCriteria) {
        object.newAcceptanceCriteriaId = acceptanceCriteria.id;
    };

    $scope.addNewAcceptanceCriteria = function(acceptcriteria){
        if (!$scope.object.newAcceptanceCriteria) return;
        $scope.object.newAcceptanceCriteriaError = null;
        $scope.object.newAcceptanceCriteriaLoading = true;

        $http.get(tfEncoder.encode("/configuration/acceptcriterias/" + acceptcriteria.id + "/add/" + $scope.object.id)).
            success(function(data, status, headers, config) {
                if (data.success) {
                    $scope.object.newAcceptanceCriteria = null;
                    threadFixModalService.addElement($scope.object.acceptanceCriterias, data.object);

                    for (var i = 0; i < $scope.acceptanceCriterias.length; i++ ) {
                        if (acceptcriteria.id == $scope.acceptanceCriterias[i].id){
                            $scope.acceptanceCriterias.splice(i,1);
                            break;
                        }
                    }

                    $scope.object.acceptanceCriterias.sort(nameCompare);
                }
                else {
                    $scope.object.newAcceptanceCriteriaError = data.message;
                }
                $scope.object.acceptanceCriteriasExpanded = true;
            }).
            error(function(data, status, headers, config) {
                $scope.error = "Failure. HTTP status was " + status;
            });
        $scope.object.newAcceptanceCriteriaLoading = false;
    };

    $scope.deleteAcceptanceCriteria = function(acceptanceCriteria){
        if (confirm("Delete this acceptance criteria?")) {
            $http.get(tfEncoder.encode("/configuration/acceptcriterias/" + acceptanceCriteria.id + "/remove/" + $scope.object.id)).
                success(function(data, status, headers, config) {
                    if (data.success) {
                        threadFixModalService.deleteElement($scope.object.acceptanceCriterias, acceptanceCriteria);
                        threadFixModalService.addElement($scope.acceptanceCriterias, acceptanceCriteria);
                        $scope.acceptanceCriterias.sort(nameCompare);
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
            assignedAcceptanceCriterias: $scope.object.acceptanceCriterias,
            availableAcceptanceCriterias: $scope.acceptanceCriterias
        });
    };
});