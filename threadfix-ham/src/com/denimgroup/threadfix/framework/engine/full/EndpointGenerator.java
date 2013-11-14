package com.denimgroup.threadfix.framework.engine.full;

import org.jetbrains.annotations.NotNull;

import java.util.List;

public interface EndpointGenerator {

    @NotNull
	List<Endpoint> generateEndpoints();
	
}
