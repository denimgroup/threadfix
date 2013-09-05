package com.denimgroup.threadfix.scanagent;

public interface ServerConduit {
	public void sendStatusUpdate(int taskId, String message);
}
