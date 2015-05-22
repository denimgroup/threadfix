package com.denimgroup.threadfix.data.dao.hibernate;

import com.denimgroup.threadfix.data.dao.AbstractObjectDao;
import com.denimgroup.threadfix.data.dao.ScanResultFilterDao;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.ScanResultFilter;
import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Projections;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class HibernateScanResultFilterDao extends AbstractObjectDao<ScanResultFilter> implements ScanResultFilterDao {

    @Autowired
    public HibernateScanResultFilterDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    protected Class<ScanResultFilter> getClassReference() {
        return ScanResultFilter.class;
    }

    @Override
    public void delete(ScanResultFilter scanResultFilter) {
        sessionFactory.getCurrentSession().delete(scanResultFilter);
    }

    @Override
    public List<GenericSeverity> loadFilteredSeveritiesForChannelType(ChannelType channelType) {

        Criteria criteria = sessionFactory.getCurrentSession().createCriteria(ScanResultFilter.class)
                .add(Restrictions.eq("channelType", channelType))
                .setProjection(Projections.property("genericSeverity"));

        return criteria.list();
    }

    @Override
    public ScanResultFilter loadByChannelTypeAndSeverity(ChannelType channelType, GenericSeverity genericSeverity) {

        Criteria criteria = sessionFactory.getCurrentSession().createCriteria(ScanResultFilter.class)
                .add(Restrictions.eq("channelType", channelType))
                .add(Restrictions.eq("genericSeverity", genericSeverity));

        List<ScanResultFilter> scanResultFilters = criteria.list();

        if(scanResultFilters == null || scanResultFilters.isEmpty()){
            return null;
        }

        return scanResultFilters.get(0);
    }
}
