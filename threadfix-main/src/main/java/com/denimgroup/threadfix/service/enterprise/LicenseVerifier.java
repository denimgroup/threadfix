////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.service.enterprise;

import com.denimgroup.threadfix.logging.SanitizedLogger;

import javax.xml.bind.DatatypeConverter;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by mac on 4/16/14.
 */
public class LicenseVerifier {

    private static final SanitizedLogger log = new SanitizedLogger(LicenseVerifier.class);

    private static String base64PublicKey = "MIIBtzCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYQAAoGAHvCFc6lrYx7DMbIU/5aklNzvYr9Omxd6hoFBmo3D62VICYANbUIUjGr03VOvc/6RMSjX4iyx2/qCxJwratoNxrht75gBweP4Zz/hmSO0bvMXNpsRurjYACkUrO01rVnEu9wUKXnGmjURYTp250dC+292QDKtoL6kd2n6GlEj4TY=";

    static boolean isValid(String contents, String signature) {
        try {

            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");

            byte[] publicKeyBytes = DatatypeConverter.parseBase64Binary(base64PublicKey);

            PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

            Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
            dsa.initVerify(pubKey);

            dsa.update(contents.getBytes());

            return dsa.verify(DatatypeConverter.parseBase64Binary(signature));

        } catch (NoSuchAlgorithmException | NoSuchProviderException | SignatureException |
                InvalidKeyException | InvalidKeySpecException e) {
            log.error("Exception encountered. Enterprise will not work until this configuration is fixed.", e);
        }

        return false;
    }
}
