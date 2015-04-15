package com.denimgroup.threadfix.importer.update.impl;

import java.io.BufferedReader;
import java.io.IOException;

import javax.annotation.Nonnull;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Service;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

import com.denimgroup.threadfix.annotations.MappingsUpdater;
import com.denimgroup.threadfix.data.dao.DefaultTagDao;
import com.denimgroup.threadfix.data.entities.DefaultTag;
import com.denimgroup.threadfix.importer.update.Updater;
import com.denimgroup.threadfix.importer.update.UpdaterConstants;
import com.denimgroup.threadfix.logging.SanitizedLogger;

@MappingsUpdater
@Service
public class DefaultTagUpdater extends SpringBeanAutowiringSupport implements Updater, Ordered {

	private static final SanitizedLogger LOG = new SanitizedLogger(DefaultTagUpdater.class);

	@Autowired
	private DefaultTagDao defaultTagDao;

	@Override
	public void doUpdate(@Nonnull String fileName, @Nonnull BufferedReader reader) throws IOException {

		LOG.info("Updating default tag information from file " + fileName);
		String line = reader.readLine();

		while (line != null) {
			String[] splitLine = StringUtils.split(line, ',');

			if (splitLine.length == 2) {
				DefaultTag tag = defaultTagDao.retrieveByName(splitLine[0]);

				if (tag == null) {
					// let's create one
					tag = new DefaultTag();
					tag.setName(splitLine[0]);
					tag.setFullClassName(splitLine[1]);
					defaultTagDao.saveOrUpdate(tag);
					LOG.info("Created a Defect Tracker with name "
							+ splitLine[0]);

				} else {
					LOG.info("Already had an entry for " + splitLine[0]);
					tag.setFullClassName(splitLine[1]);
					defaultTagDao.saveOrUpdate(tag);
				}

			} else {
				LOG.error("Line had " + splitLine.length
						+ " sections instead of 2: " + line);
			}
			line = reader.readLine();
		}
	}

	@Override
	public String getFolder() {
		return UpdaterConstants.DEFAULT_TAGS_FOLDER;
	}

	@Override
	public int getOrder() {
		return 600;
	}
}