////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
package com.denimgroup.threadfix.service.bootstrap;

import com.denimgroup.threadfix.data.entities.RemoteProviderType;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.service.RemoteProviderTypeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Created by mcollins on 8/21/15.
 */
@Component
public class RemoteProviderBootstrapper {

    private static final SanitizedLogger LOG = new SanitizedLogger(RemoteProviderBootstrapper.class);

    @Autowired
    RemoteProviderTypeService remoteProviderTypeService;

    public void bootstrap() {

        String whitehat = "WhiteHat Sentinel",
                veracode = "Veracode",
                qualys = "QualysGuard WAS";

        LOG.info("Inserting initial Remote Providers.");

        RemoteProviderType whitehatType = new RemoteProviderType();
        whitehatType.setName(whitehat);
        whitehatType.setHasApiKey(true);
        whitehatType.setHasUserNamePassword(false);

        remoteProviderTypeService.store(whitehatType);


        RemoteProviderType veracodeType = new RemoteProviderType();
        veracodeType.setName(veracode);
        veracodeType.setHasApiKey(false);
        veracodeType.setHasUserNamePassword(true);

        remoteProviderTypeService.store(veracodeType);


        RemoteProviderType qualysType = new RemoteProviderType();
        qualysType.setName(qualys);
        qualysType.setHasApiKey(false);
        qualysType.setHasUserNamePassword(true);

        remoteProviderTypeService.store(qualysType);

        LOG.info("Finished inserting initial Remote Providers.");

    }


}
