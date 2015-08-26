package com.denimgroup.threadfix.data.dao.hibernate;

import com.denimgroup.threadfix.data.dao.AbstractObjectDao;
import com.denimgroup.threadfix.data.dao.ScanResultFilterDao;
import com.denimgroup.threadfix.data.entities.ChannelType;
import com.denimgroup.threadfix.data.entities.GenericSeverity;
import com.denimgroup.threadfix.data.entities.ScanResultFilter;
import com.denimgroup.threadfix.data.entities.ScannerType;
import org.hibernate.Criteria;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.LogicalExpression;
import org.hibernate.criterion.Projections;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

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

    // idk if this is better than just raw Java but it was fun to write
    @Override
    public List<Integer> retrieveAllChannelSeverities() {

        List<ScanResultFilter> filters = retrieveAll();

       return retrieveAllChannelSeverities(filters);
    }

    @Override
    public List<Integer> retrieveAllChannelSeveritiesByChannelType(ChannelType channelType) {

        Criteria criteria = sessionFactory.getCurrentSession().createCriteria(ScanResultFilter.class)
                .add(Restrictions.eq("channelType", channelType));

        List<ScanResultFilter> filters = criteria.list();
        return retrieveAllChannelSeverities(filters);
    }

    private List<Integer> retrieveAllChannelSeverities(List<ScanResultFilter> filters) {

        if (filters.isEmpty()) {
            return list();
        }

        Criteria criteria = sessionFactory.getCurrentSession().createCriteria(ScanResultFilter.class)
                .createAlias("genericSeverity", "genericSeverityAlias")
                .createAlias("genericSeverityAlias.severityMapping", "mappingAlias")
                .createAlias("mappingAlias.channelSeverity", "channelSeverityAlias")
                .createAlias("channelSeverityAlias.channelType", "channelTypeAlias")
                .setProjection(Projections.property("channelSeverityAlias.id"));

        LogicalExpression wherePart = null;
        for (ScanResultFilter filter : filters) {

            if (wherePart == null) {
                wherePart = getLogicalExpression(filter);
            } else {
                wherePart = Restrictions.or(wherePart, getLogicalExpression(filter));
            }
        }

        return criteria.add(wherePart).list();
    }

    private LogicalExpression getLogicalExpression(ScanResultFilter filter) {

        ChannelType alternateChannelType = filter.getChannelType();

        if (alternateChannelType.getName().equals(ScannerType.APPSCAN_ENTERPRISE.getDisplayName())) {
            alternateChannelType = retrieveChannelTypeByName(ScannerType.APPSCAN_DYNAMIC.getDisplayName());
        }

        if (alternateChannelType.getName().equals(ScannerType.DEPENDENCY_CHECK.getDisplayName())
                || alternateChannelType.getName().equals(ScannerType.SSVL.getDisplayName())) {
            alternateChannelType = retrieveChannelTypeByName(ScannerType.MANUAL.getDisplayName());
        }

        return Restrictions.and(
                Restrictions.eq("genericSeverityAlias.intValue", filter.getGenericSeverity().getIntValue()),
                Restrictions.eq("channelTypeAlias.id", alternateChannelType.getId())
        );
    }

    private ChannelType retrieveChannelTypeByName(String name) {
        Criteria criteria = sessionFactory.getCurrentSession().createCriteria(ChannelType.class)
                .add(Restrictions.eq("name", name));

        List<ChannelType> channelTypeList = criteria.list();

        if(channelTypeList == null || channelTypeList.isEmpty()){
            return null;
        }

        return channelTypeList.get(0);
    }
}
