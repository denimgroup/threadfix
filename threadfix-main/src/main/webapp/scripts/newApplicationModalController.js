var myAppModule = angular.module('threadfix')

myAppModule.controller('NewApplicationModalController', function ($scope, $modalInstance, threadFixModalService, team, csrfToken) {

    $scope.application = {
        team: {
            id: team.id,
            name: team.name
        },
        applicationCriticality: {
            id: 2
        },
        frameworkType: 'Detect'
    };

    $scope.loading = false;


    $scope.ok = function (valid) {

        if (valid) {
            $scope.loading = true;

            var url = "/organizations/" + team.id + "/modalAddApp" + csrfToken;

            threadFixModalService.post(url, $scope.application).
                success(function(data, status, headers, config) {
                    $scope.loading = false;

                    if (data.success) {
                        team.applications.push(data.object)
                        $modalInstance.close($scope.application);
                    } else {
                        $scope.error = "Failure. Message was : " + data.message;
                    }
                }).
                error(function(data, status, headers, config) {
                    $scope.loading = false;
                    $scope.error = "Failure. HTTP status was " + status;
                });
        }
    };

    $scope.cancel = function () {
        $modalInstance.dismiss('cancel');
    };
});
