var myAppModule = angular.module('threadfix')

myAppModule.controller('TagDetailPageController', function ($scope, $window, $http, $rootScope, tfEncoder) {

    $scope.tagId = $window.location.pathname.match(/([0-9]+)/)[0];
    $scope.currentUrl = "/configuration/tags/" + $scope.tagId;
    $scope.$on('rootScopeInitialized', function() {
        $scope.loading = true;
        $http.get(tfEncoder.encode($scope.currentUrl + '/objects')).
            success(function(data, status, headers, config) {
                $scope.loading = false;
                if (data.success) {
                    $scope.appList = data.object.appList;
                    $scope.commentList = data.object.commentList;
                    getVulnList();
                } else {
                    $scope.errorMessage = "Failure. Message was : " + data.message;
                }
            }).
            error(function(data, status, headers, config) {
                $scope.loading = false;
                $scope.errorMessage = "Failed to retrieve waf list. HTTP status was " + status;
            });
    });

    var getVulnList = function(){
        var vulnMap = {};
        $scope.commentList.forEach(function(comment) {
            if (comment.commentInfo.vulnerabilityId) {
                if (!vulnMap[comment.commentInfo.vulnerabilityId]) {
                    vulnMap[comment.commentInfo.vulnerabilityId] = {
                        id : comment.commentInfo.vulnerabilityId,
                        genericVulnerability: {
                            name: comment.commentInfo.vulnerabilityName
                        },
                        app : {
                            id: comment.commentInfo.applicationId,
                            name: comment.commentInfo.applicationName
                        },
                        team : {
                            id: comment.commentInfo.teamId,
                            name: comment.commentInfo.teamName
                        },
                        vulnerabilityComments : [{
                            id: comment.commentInfo.commentId,
                            comment: comment.commentInfo.comment,
                            tags: comment.commentInfo.tags,
                            username: comment.commentInfo.username,
                            time: comment.commentInfo.time
                        }],
                        genericSeverity : comment.commentInfo.genericSeverity
                    }
                } else {
                    vulnMap[comment.commentInfo.vulnerabilityId].vulnerabilityComments.push({
                        id: comment.commentInfo.commentId,
                        comment: comment.commentInfo.comment,
                        tags: comment.commentInfo.tags,
                        username: comment.commentInfo.username,
                        time: comment.commentInfo.time
                    })
                }
            }
        })

        $scope.allVulnList = [];
        var keys = Object.keys(vulnMap);
        keys.forEach(function(key){
            $scope.allVulnList.push(vulnMap[key]);
        });

        $scope.allVulnList.sort(function(vuln1, vuln2){
            return vuln1.vulnerabilityComments.length - vuln2.vulnerabilityComments.length;
        });

        $scope.$broadcast("complianceVulnList", $scope.allVulnList);
    }

    $scope.goToApp = function(app) {
        $window.location.href = tfEncoder.encode("/organizations/" + app.team.id + "/applications/" + app.id);
    };

    $scope.goToTeam = function(app) {
        $window.location.href = tfEncoder.encode("/organizations/" + app.team.id);
    };

});
