package com.denimgroup.threadfix.data.dao.hibernate;

import com.denimgroup.threadfix.data.dao.AbstractObjectDao;
import com.denimgroup.threadfix.data.dao.CustomCweTextDao;
import com.denimgroup.threadfix.data.entities.CustomCweText;
import com.denimgroup.threadfix.data.entities.GenericVulnerability;
import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class HibernateCustomCweTextDao extends AbstractObjectDao<CustomCweText> implements CustomCweTextDao{

    @Autowired
    public HibernateCustomCweTextDao(SessionFactory sessionFactory){
        super(sessionFactory);
    }

    @Override
    protected Class<CustomCweText> getClassReference() {
        return CustomCweText.class;
    }

    @Override
    public void delete(CustomCweText customCweText) {
        sessionFactory.getCurrentSession().delete(customCweText);
    }

    @Override
    public CustomCweText retrieveByGenericVulnerability(GenericVulnerability genericVulnerability) {

        Criteria criteria = sessionFactory.getCurrentSession().createCriteria(CustomCweText.class)
                .add(Restrictions.eq("genericVulnerability", genericVulnerability));

        List<CustomCweText> customCweTexts = criteria.list();

        if(customCweTexts == null || customCweTexts.isEmpty()){
            return null;
        }

        return customCweTexts.get(0);
    }
}
