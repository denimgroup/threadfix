angular.module('d3donut', ['d3'])
    .factory('d3donut',['d3', function(d3){

        var Donut3D={};

        function pieTop(d, rx, ry, ir ){
            if(d.endAngle - d.startAngle == 0 ) return "M 0 0";
            var sx = rx*Math.cos(d.startAngle),
                sy = ry*Math.sin(d.startAngle),
                ex = rx*Math.cos(d.endAngle),
                ey = ry*Math.sin(d.endAngle);

            var ret =[];
            ret.push("M",sx,sy,"A",rx,ry,"0",(d.endAngle-d.startAngle > Math.PI? 1: 0),"1",ex,ey,"L",ir*ex,ir*ey);
            ret.push("A",ir*rx,ir*ry,"0",(d.endAngle-d.startAngle > Math.PI? 1: 0), "0",ir*sx,ir*sy,"z");
            return ret.join(" ");
        }

        function pieOuter(d, rx, ry, h ){
            var startAngle = (d.startAngle > Math.PI ? Math.PI : d.startAngle);
            var endAngle = (d.endAngle > Math.PI ? Math.PI : d.endAngle);

            var sx = rx*Math.cos(startAngle),
                sy = ry*Math.sin(startAngle),
                ex = rx*Math.cos(endAngle),
                ey = ry*Math.sin(endAngle);

            var ret =[];
            ret.push("M",sx,h+sy,"A",rx,ry,"0 0 1",ex,h+ey,"L",ex,ey,"A",rx,ry,"0 0 0",sx,sy,"z");
            return ret.join(" ");
        }

        function pieInner(d, rx, ry, h, ir ){
            var startAngle = (d.startAngle < Math.PI ? Math.PI : d.startAngle);
            var endAngle = (d.endAngle < Math.PI ? Math.PI : d.endAngle);

            var sx = ir*rx*Math.cos(startAngle),
                sy = ir*ry*Math.sin(startAngle),
                ex = ir*rx*Math.cos(endAngle),
                ey = ir*ry*Math.sin(endAngle);

            var ret =[];
            ret.push("M",sx, sy,"A",ir*rx,ir*ry,"0 0 1",ex,ey, "L",ex,h+ey,"A",ir*rx, ir*ry,"0 0 0",sx,h+sy,"z");
            return ret.join(" ");
        }

        function getPercent(d){
            return (d.endAngle-d.startAngle > 0.2 ?
                Math.round(1000*(d.endAngle-d.startAngle)/(Math.PI*2))/10+'%' : '');
        }

        Donut3D.transition = function(id, data, rx, ry, h, ir){
            function arcTweenInner(a) {
                var i = d3.interpolate(this._current, a);
                this._current = i(0);
                return function(t) { return pieInner(i(t), rx+0.5, ry+0.5, h, ir);  };
            }
            function arcTweenTop(a) {
                var i = d3.interpolate(this._current, a);
                this._current = i(0);
                return function(t) { return pieTop(i(t), rx, ry, ir);  };
            }
            function arcTweenOuter(a) {
                var i = d3.interpolate(this._current, a);
                this._current = i(0);
                return function(t) { return pieOuter(i(t), rx-.5, ry-.5, h);  };
            }
            function textTweenX(a) {
                var i = d3.interpolate(this._current, a);
                this._current = i(0);
                return function(t) { return 0.6*rx*Math.cos(0.5*(i(t).startAngle+i(t).endAngle));  };
            }
            function textTweenY(a) {
                var i = d3.interpolate(this._current, a);
                this._current = i(0);
                return function(t) { return 0.6*rx*Math.sin(0.5*(i(t).startAngle+i(t).endAngle));  };
            }

            var _data = d3.layout.pie().sort(null).value(function(d) {return d.value;})(data);

            d3.select("#"+id).selectAll(".innerSlice").data(_data)
                .transition().duration(750).attrTween("d", arcTweenInner);

            d3.select("#"+id).selectAll(".topSlice").data(_data)
                .transition().duration(750).attrTween("d", arcTweenTop);

            d3.select("#"+id).selectAll(".outerSlice").data(_data)
                .transition().duration(750).attrTween("d", arcTweenOuter);

            d3.select("#"+id).selectAll(".percent").data(_data).transition().duration(750)
                .attrTween("x",textTweenX).attrTween("y",textTweenY).text(getPercent);
        }

        Donut3D.draw=function(id, data, x /*center x*/, y/*center y*/,
                              rx/*radius x*/, ry/*radius y*/, h/*height*/, ir/*inner radius*/){

            var _data = d3.layout.pie().sort(null).value(function(d) {return d.value;})(data);

            var key = function(d){ return d.data.label; };
            var svg = d3.select("#"+id).append("g").attr("transform", "translate(" + x + "," + y + ")");

            var slices = svg.append("g")
                .attr("class", "slices")
//            var labels =svg.append("g")
//                .attr("class", "labels")
//            var lines = svg.append("g")
//                .attr("class", "lines");

            slices.selectAll(".innerSlice").data(_data).enter().append("path").attr("class", "innerSlice")
                .style("fill", function(d) { return d3.hsl(d.data.color).darker(0.7); })
                .attr("d",function(d){ return pieInner(d, rx+0.5,ry+0.5, h, ir);})
                .each(function(d){this._current=d;});

            slices.selectAll(".topSlice").data(_data).enter().append("path").attr("class", "topSlice")
                .style("fill", function(d) { return d.data.color; })
                .style("stroke", function(d) { return d.data.color; })
                .attr("d",function(d){ return pieTop(d, rx, ry, ir);})
                .each(function(d){this._current=d;});

            slices.selectAll(".outerSlice").data(_data).enter().append("path").attr("class", "outerSlice")
                .style("fill", function(d) { return d3.hsl(d.data.color).darker(0.7); })
                .attr("d",function(d){ return pieOuter(d, rx-.5,ry-.5, h);})
                .each(function(d){this._current=d;});

            slices.selectAll(".percent").data(_data).enter().append("text").attr("class", "percent")
                .attr("x",function(d){ return 0.6*rx*Math.cos(0.5*(d.startAngle+d.endAngle));})
                .attr("y",function(d){ return 0.6*ry*Math.sin(0.5*(d.startAngle+d.endAngle));})
                .text(getPercent).each(function(d){this._current=d;});

            /* ------- LEGEND -------*/
            var legend = svg.selectAll(".legend")
                .data(_data)
                .enter().append("g")
                .attr("class", "legend")
                .attr("transform", function(d, i) { return "translate(0," + i * 20 + ")"; });

            legend.append("rect")
                .attr("x", 170 - 18)
                .attr("width", 18)
                .attr("height", 18)
                .style("fill", function(d) { return d.data.color; });

            legend.append("text")
                .attr("x", 170 - 24)
                .attr("y", 9)
                .attr("dy", ".35em")
                .style("text-anchor", "end")
                .text(function(d) { return d.value + ': ' + d.data.label; });

//            /* ------- TEXT LABELS -------*/
//
//            var radius = 75;
//
//            var arc = d3.svg.arc()
//                .outerRadius(radius * 0.8)
//                .innerRadius(radius * 0.4);
//
//            var outerArc = d3.svg.arc()
//                .innerRadius(radius * 0.9)
//                .outerRadius(radius * 0.9);
//
//            var text = labels.selectAll("text")
//                .data(_data, key);
//
//            text.enter()
//                .append("text")
//                .attr("dy", ".35em")
//                .text(function(d) {
//                    return getLabel(d);
//                });
//
//            function midAngle(d){
//                return d.startAngle + (d.endAngle - d.startAngle)/2;
//            }
//
//            function modifyAngles(d) {
//                d.startAngle = d.startAngle + Math.PI/2;
//                d.endAngle = d.endAngle + Math.PI/2;
//                return d;
//            }
//
//            text.transition().duration(1000)
//                .attrTween("transform", function(d) {
//                    this._current = this._current || d;
//                    var interpolate = d3.interpolate(this._current, d);
//                    this._current = interpolate(0);
//                    return function(t) {
//                        var d2 = interpolate(t);
//                        d2 = modifyAngles(d2);
//                        var pos = outerArc.centroid(d2);
//                        pos[0] = radius * (midAngle(d2) < Math.PI || midAngle(d2) > 2*Math.PI ? 1 : -1);
//                        return "translate("+ pos +")";
//                    };
//                })
//                .styleTween("text-anchor", function(d){
//                    this._current = this._current || d;
//                    var interpolate = d3.interpolate(this._current, d);
//                    this._current = interpolate(0);
//                    return function(t) {
//                        var d2 = interpolate(t);
//                        d2 = modifyAngles(d2);
//                        return midAngle(d2) < Math.PI || midAngle(d2) > 2*Math.PI ? "start":"end";
//                    };
//                });
//
//            text.exit()
//                .remove();
//
//            /* ------- SLICE TO TEXT POLYLINES -------*/
//
//            var polyline = lines.selectAll("polyline")
//                .data(_data, key);
//
//            polyline.enter()
//                .append("polyline");
//
//            polyline.transition().duration(1000)
//                .attrTween("points", function(d){
//                    this._current = this._current || d;
//                    var interpolate = d3.interpolate(this._current, d);
//                    this._current = interpolate(0);
//                    if (d.value === 0)
//                        return null;
//                    return function(t) {
//                        var d2 = interpolate(t);
//                        d2 = modifyAngles(d2);
//                        var pos = outerArc.centroid(d2);
//                        pos[0] = radius * 0.95 * (midAngle(d2) < Math.PI || midAngle(d2) > 2*Math.PI ? 1 : -1);
//                        return [arc.centroid(d2), outerArc.centroid(d2), pos];
//                    };
//                });
//
//            polyline.exit()
//                .remove();
        }

        return Donut3D;
    }]);