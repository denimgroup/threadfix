package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.dao.CustomCweTextDao;
import com.denimgroup.threadfix.data.entities.CustomCweText;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional(readOnly = false)
public class CustomCweServiceImpl implements CustomCweTextService{

    protected final SanitizedLogger log = new SanitizedLogger(CustomCweServiceImpl.class);

    @Autowired
    private CustomCweTextDao customCweTextDao;

    @Override
    public List<CustomCweText> loadAll() {
        return customCweTextDao.retrieveAll();
    }

    @Override
    public CustomCweText loadById(int id) {
        return customCweTextDao.retrieveById(id);
    }

    @Override
    public void store(CustomCweText customCweText) {
        customCweTextDao.saveOrUpdate(customCweText);
    }

    @Override
    public void delete(CustomCweText customCweText) {
        customCweTextDao.delete(customCweText);
    }

    @Override
    public CustomCweText loadByGenericVulnerability(GenericVulnerability genericVulnerability) {
        return customCweTextDao.retrieveByGenericVulnerability(genericVulnerability);
    }
}
