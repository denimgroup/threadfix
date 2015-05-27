package com.denimgroup.threadfix.importer.impl.remoteprovider;

import com.denimgroup.threadfix.annotations.RemoteProvider;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtils;

import java.util.List;

import static com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtilsImpl.getImpl;

/**
 * Created by skakani on 5/26/2015.
 */
@RemoteProvider(name = "IBM Rational AppScan Enterprise")
public class AppScanEnterpriseRemoteProvider extends AbstractRemoteProvider{
    public static final String
                USERNAME = "Username",
                PASSWORD = "Password";

    public AppScanEnterpriseRemoteProvider() {
      super(ScannerType.APPSCAN_ENTERPRISE);
    }

    RemoteProviderHttpUtils httpUtils = getImpl(AppScanEnterpriseRemoteProvider.class);

    @Override
    public List<RemoteProviderApplication> fetchApplications(){

        return null;

    }

    @Override
    public List<Scan> getScans(RemoteProviderApplication remoteProviderApplication){
        return null;
    }



}
