package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.entities.CustomCweText;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;

import java.util.List;

public interface CustomCweTextService {

    List<CustomCweText> loadAll();

    CustomCweText loadById(int id);

    void store(CustomCweText customCweText);

    void delete(CustomCweText customCweText);

    CustomCweText loadByGenericVulnerability(GenericVulnerability genericVulnerability);
}
