var d3ThreadfixModule = angular.module('threadfix');

// Point in time
d3ThreadfixModule.directive('d3Pointintime', ['$window', '$timeout', 'd3', 'd3donut', 'reportExporter', 'd3Service', 'reportConstants', 'reportUtilities',
    function($window, $timeout, d3, d3donut, reportExporter, d3Service, reportConstants, reportUtilities) {
        return {
            restrict: 'EA',
            scope: {
                data: '=',
                label: '=',
                updateTree: '&'
            }
            ,
            link: function(scope, ele) {

                var color = d3Service.getColorScale(d3, reportConstants.vulnTypeColorList);

                scope.$watch('data', function(newVals) {
                    scope.render(newVals);
                }, true);

                scope.render = function (reportData) {
                    var data = angular.copy(reportData);

                    if (!data)
                        return;

                    color.domain(reportConstants.vulnTypeList);

                    var pieDim ={w:670, h: 400};

                    var svg = d3Service.getExistingSvg(d3, ele[0], pieDim.w, pieDim.h)
                        .attr("transform", "translate("+pieDim.w/2+","+pieDim.h/2+")");


                    svg.selectAll('*').remove();
                    reportUtilities.drawTitle(svg, pieDim.w, scope.label.teams, scope.label.apps, "Point in Time Report", 20);

                    var id = "pointInTimeDonut";

                    svg.append("g").attr("id",id);

//                    d3donut.draw3D(id, getData(), pieDim.w/2, pieDim.h/3 + 10, 100, 70, 30, 0.4);
                    d3donut.draw2D(id, getData(), pieDim.h, pieDim.w, 100, false, scope.updateTree);

                    var tableData = [];
                    tableData.push(data.Critical);
                    tableData.push(data.High);
                    tableData.push(data.Medium);
                    tableData.push(data.Low);
                    tableData.push(data.Info);

                    var legend = svg.selectAll(".legend")
                        .data(tableData)
                        .enter().append("g")
                        .attr("class", "legend")
                        .attr("transform", function(d, i) { return "translate(0," + (300 + i * 20) + ")"; });

                    legend.append("rect")
                        .attr("x", 40)
                        .attr("width", 18)
                        .attr("height", 18)
                        .style("fill", function(d){return color(d.Severity)});

                    legend.append("text")
                        .attr("x", 64)
                        .attr("y", 9)
                        .attr("dy", ".70em")
                        .style("text-anchor", "start")
                        .text(function(d) { return d.Severity; });

                    legend.append("text")
                        .attr("x", 120)
                        .attr("y", 9)
                        .attr("dy", ".35em")
                        .style("text-anchor", "start")
                        .text(function(d) { return d.Count + "(" + d.Percentage + ")"; });

                    legend.append("text")
                        .attr("x", 200)
                        .attr("y", 9)
                        .attr("dy", ".35em")
                        .style("text-anchor", "start")
                        .text(function(d) { return "Average Age: " + d.Avg_Age; });

                    function getData(){
                        return color.domain().map(function(vulnType) {
                            return {tip:vulnType, value:data[vulnType]['Count'], fillColor:color(vulnType), severity: vulnType};});
                    }
                };
                ;
            }
        }
    }]);
