package com.denimgroup.threadfix.service;

import com.denimgroup.threadfix.data.dao.DefectTrackerTypeDao;
import com.denimgroup.threadfix.data.dao.GenericObjectDao;
import com.denimgroup.threadfix.data.entities.DefectTrackerType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = false)
public class DefectTrackerTypeServiceImpl extends AbstractGenericObjectService<DefectTrackerType> implements DefectTrackerTypeService{

    @Autowired
    private DefectTrackerTypeDao defectTrackerTypeDao;

    @Override
    GenericObjectDao getDao() {
        return defectTrackerTypeDao;
    }
}
