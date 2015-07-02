package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

@Service
public class NonceServiceImpl implements NonceService {

    //	TODO - Move the creation of SecureRandoms into some sort of shared facility
    //	for the entire application (each class doesn't need to repeat this code)
    private static final String RANDOM_ALGORITHM = "SHA1PRNG";
    private static final String RANDOM_PROVIDER = "SUN";

    private SecureRandom randomSource = null;

    private final SanitizedLogger log = new SanitizedLogger(NonceServiceImpl.class);

    @Override
    /**
     * Generate a once time token (nonce) for authenticating subsequent
     * requests. This will also add the token to the session. The nonce
     * generation is a simplified version of ManagerBase.generateSessionId().
     *
     */
    public String generateNonce() {
        byte random[] = new byte[16];

        // Render the result as a String of hexadecimal digits
        StringBuilder buffer = new StringBuilder();

        if (randomSource == null) {
            try {
                randomSource = SecureRandom.getInstance(RANDOM_ALGORITHM, RANDOM_PROVIDER);
            } catch (NoSuchAlgorithmException e) {
                log.error("Unable to find algorithm " + RANDOM_ALGORITHM, e);
            } catch (NoSuchProviderException e) {
                log.error("Unable to find provider " + RANDOM_PROVIDER, e);
            }
        }

        if (randomSource == null) {
            return null;
        }

        randomSource.nextBytes(random);

        for (byte element : random) {
            byte b1 = (byte) ((element & 0xf0) >> 4);
            byte b2 = (byte) (element & 0x0f);
            if (b1 < 10) {
                buffer.append((char) ('0' + b1));
            } else {
                buffer.append((char) ('A' + (b1 - 10)));
            }

            if (b2 < 10) {
                buffer.append((char) ('0' + b2));
            } else {
                buffer.append((char) ('A' + (b2 - 10)));
            }
        }

        return buffer.toString();
    }
}
