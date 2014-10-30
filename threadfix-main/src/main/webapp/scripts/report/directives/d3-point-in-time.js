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
                var pieDim ={w:670, h: 350};

                scope.$watch('data', function(newVals) {
                    scope.render(newVals);
                }, true);

                scope.$watch('label', function(newVals) {
                    scope.render(scope.data);
                }, true);

                scope.render = function (reportData) {
                    var data = angular.copy(reportData);
                    if (!data)
                        return;

                    color.domain(reportConstants.vulnTypeList);
                    var svg = d3Service.getExistingSvg(d3, ele[0], pieDim.w, pieDim.h);

                    svg.selectAll('*').remove();
                    reportUtilities.drawTitle(svg, pieDim.w, scope.label, "Point in Time Report", 30);

                    if (Object.keys(data).length === 0) {
                        svg.append("g")
                            .append("text")
                            .attr("x", pieDim.w/2)
                            .attr("y", 130)
                            .attr("class", "warning")
                            .text("Select fields to display")
                        return;
                    }

                    var id = "pointInTimeDonut";

                    svg.append("g").attr("id",id);

                    d3donut.draw2D(id, getData(), pieDim.h, pieDim.w, 150, 200 , 100, true, scope.label);

                    var tableData = [];
                    if (data.Critical)
                        tableData.push(data.Critical);
                    if (data.High)
                        tableData.push(data.High);
                    if (data.Medium)
                        tableData.push(data.Medium);
                    if (data.Low)
                        tableData.push(data.Low);
                    if (data.Info)
                        tableData.push(data.Info);

                    var legend = svg.selectAll(".legend")
                        .data(tableData)
                        .enter().append("g")
                        .attr("class", "legend")
                        .attr("id", function(d){return "legend" + d.Severity;})
                        .attr("transform", function(d, i) { return "translate(300," + (150 + i * 20) + ")"; });

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
                        var _data = [];
                        color.domain().map(function(vulnType) {
                            if (data[vulnType])
                                _data.push({tip:vulnType, value:data[vulnType]['Count'], fillColor:color(vulnType), severity: vulnType});
                        });
                        return _data;
                    }
                };
                ;
            }
        }
    }]);
