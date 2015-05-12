package com.denimgroup.threadfix.data.dao;

import com.denimgroup.threadfix.data.entities.CustomCweText;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;

public interface CustomCweTextDao extends GenericObjectDao<CustomCweText>{
    void delete(CustomCweText customCweText);

    CustomCweText retrieveByGenericVulnerability(GenericVulnerability genericVulnerability);
}
