var d3ThreadfixModule = angular.module('threadfix');

// Point in time
d3ThreadfixModule.directive('d3PointInTime', ['$window', '$timeout', 'd3', 'd3donut', 'reportExporter', 'd3Service', 'reportConstants', 'reportUtilities', 'customSeverityService',
    function($window, $timeout, d3, d3donut, reportExporter, d3Service, reportConstants, reportUtilities, customSeverityService) {
        return {
            restrict: 'EA',
            scope: {
                data: '=',
                label: '=',
                averageAges: '=',
                genericSeverities: '='
            }
            ,
            link: function(scope, ele) {

                var color = d3Service.getColorScale(d3, reportConstants.vulnTypeColorList);
                var pieDim ={w:670, h: 350};
                var svg;
                var data;
                var total = 0;

                scope.$watch('data', function(newVals) {
                    scope.render(newVals);
                }, true);

                scope.$watch('averageAges', function() {
                    drawLegend();
                }, true);

                scope.$watch('label', function(newVals) {
                    scope.render(scope.data);
                }, true);

                scope.render = function (reportData) {
                    data = angular.copy(reportData);
                    if (!data)
                        return;
                    total = 0;
                    data.sort(function(e1, e2){
                        return e1.intValue - e2.intValue;
                    });

                    color.domain(reportConstants.vulnTypeList);
                    svg = d3Service.getExistingSvg(d3, ele[0], pieDim.w, pieDim.h);
                    svg.selectAll('*').remove();
                    svg.attr("id", "pointInTimeGraph");

                    if (Object.keys(data).length === 0) {
                        svg.append("g")
                            .append("text")
                            .attr("x", pieDim.w/2)
                            .attr("y", 130)
                            .attr("class", "warning")
                            .text("No Data Found")
                        return;
                    }

                    var id = "pointInTimeDonut";
                    svg.append("rect")
                        .attr("transform", "translate(0, 0)")
                        .attr("width", pieDim.w)
                        .attr("height", pieDim.h)
                        .attr("fill", "#ffffff")
                        .attr("strokeWidth", 0);

                    reportUtilities.drawTitle(svg, pieDim.w, scope.label, "Point in Time Report", 30);

                    svg.append("g").attr("id",id);

                    d3donut.draw2D(id, getData(), pieDim.h, pieDim.w, 150, 200 , 100, true, scope.label);

                    drawLegend();

                    function getData(){
                        var _data = [];
                        data.forEach(function(element){
                            total += element.total;
                            _data.push({tip:element.name,
                                value:element.total,
                                fillColor:color(element.name),
                                severity: element.name,
                                genericSeverities: scope.genericSeverities
                            });
                        });
                        return _data;
                    };

                };

                function drawLegend(){
                    if (!svg || !scope.averageAges || !data)
                        return;

                    data.forEach(function(element){
                        scope.averageAges.forEach(function(age){
                            if (element.intValue === age.severity) {
                                element.age = Math.round(age.datediff);
                            }
                        });
                    });
                    var legend = svg.selectAll(".legend")
                        .data(data)
                        .enter().append("g")
                        .attr("class", "legend")
                        .attr("id", function(d){return "legend" + d.name;})
                        .attr("transform", function(d, i) { return "translate(300," + (150 + i * 20) + ")"; });

                    legend.append("rect")
                        .attr("x", 40)
                        .attr("width", 18)
                        .attr("height", 18)
                        .style("fill", function(d){return color(d.name)});

                    legend.append("text")
                        .attr("x", 64)
                        .attr("y", 9)
                        .attr("dy", ".70em")
                        .style("text-anchor", "start")
                        .text(function(d) {
                            return (d.name.length > 8 ? d.name.substring(0,8).concat("...") : d.name) ;
                        });

                    legend.append("text")
                        .attr("x", 120)
                        .attr("y", 9)
                        .attr("dy", ".35em")
                        .style("text-anchor", "start")
                        .text(function(d) { return d.total + "(" + (total === 0 ? "0%" : getPercent(d.total/total)) + ")"; });

                    legend.append("text")
                        .attr("x", 200)
                        .attr("y", 9)
                        .attr("dy", ".35em")
                        .style("text-anchor", "start")
                        .text(function (d) {
                            return "Average Age: " + d.age;
                        });
                };

                function getPercent(rate){
                    return Math.round(1000 * rate)/10 + "%";
                };
            }
        }
    }]);
