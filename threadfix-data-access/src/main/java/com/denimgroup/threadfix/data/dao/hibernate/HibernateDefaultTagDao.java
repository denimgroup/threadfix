package com.denimgroup.threadfix.data.dao.hibernate;

import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.denimgroup.threadfix.data.dao.AbstractNamedObjectDao;
import com.denimgroup.threadfix.data.dao.DefaultTagDao;
import com.denimgroup.threadfix.data.entities.DefaultTag;

/**
 * Hibernate Defect DAO implementation. Most basic methods are implemented in
 * the AbstractGenericDao
 *
 * @see AbstractNamedObjectDao
 */
@Repository
public class HibernateDefaultTagDao extends AbstractNamedObjectDao<DefaultTag> implements DefaultTagDao {

    @Autowired
        public HibernateDefaultTagDao(SessionFactory sessionFactory) {
            super(sessionFactory);
        }

    @Override
        protected Class<DefaultTag> getClassReference() {
            return DefaultTag.class;
        }

}
