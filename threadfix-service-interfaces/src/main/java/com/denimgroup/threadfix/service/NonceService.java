package com.denimgroup.threadfix.service;

public interface NonceService {

    /**
     * Generate a once time token (nonce) for authenticating subsequent
     * requests. This will also add the token to the session. The nonce
     * generation is a simplified version of ManagerBase.generateSessionId().
     *
     */
    String generateNonce();
}
