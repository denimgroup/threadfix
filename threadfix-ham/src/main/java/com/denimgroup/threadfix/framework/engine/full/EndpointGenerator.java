package com.denimgroup.threadfix.framework.engine.full;

import com.denimgroup.threadfix.data.interfaces.Endpoint;
import org.jetbrains.annotations.NotNull;

import java.util.List;

public interface EndpointGenerator extends Iterable<Endpoint> {

    @NotNull
	List<Endpoint> generateEndpoints();
	
}
