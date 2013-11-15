package com.denimgroup.threadfix.framework;

import static org.junit.Assert.assertTrue;

import org.jetbrains.annotations.NotNull;
import org.junit.Test;

import com.denimgroup.threadfix.framework.engine.partial.DefaultPartialMapping;
import com.denimgroup.threadfix.framework.engine.partial.PartialMapping;
import com.denimgroup.threadfix.framework.engine.partial.PartialMappingDatabase;
import com.denimgroup.threadfix.framework.engine.partial.PartialMappingsDatabaseFactory;
import com.denimgroup.threadfix.framework.enums.FrameworkType;

public class PartialMappingTests {
	
	private static final String JPA_REPO  = "java/org/springframework/samples/petclinic/repository/jpa/JpaOwnerRepositoryImpl.java";
	private static final String JDBC_REPO = "java/org/springframework/samples/petclinic/repository/jdbc/JdbcOwnerRepositoryImpl.java";
	
	@NotNull
    private String[][] petClinicFortifyData = {
		{ JDBC_REPO, "/owners" },
		{ JPA_REPO, "/owners" },
		{ JPA_REPO, "/owners/{ownerId}/pets/new" },
		{ JPA_REPO, "/owners/{ownerId}/edit" },
		{ JPA_REPO, "/owners/{ownerId}" }
	},
	petClinicAppScanData = {
		{ null, "/petclinic/" },
		{ null, "/petclinic/owners" },
		{ null, "/petclinic/owners/2/pets/new" },
		{ null, "/petclinic/owners/357/edit" },
		{ null, "/petclinic/owners/835/pets" },
		{ null, "/petclinic/owners/83/pets/new" },
		{ null, "/petclinic/owners/26/pets/26/visits/new" },
	},
	springMvcQueries = {
		{ "/petclinic/owners/2/edit", JPA_REPO },
		{ "/petclinic/owners/25235/edit", JPA_REPO },
		{ "/petclinic/owners/215/edit/", JPA_REPO },
		{ "/petclinic/owners//edit/", null },
		{ "/petclinic/owners/235", JPA_REPO },
		{ "/petclinic/owners/3462/", JPA_REPO },
		{ "/petclinic/owners//pets/new", null },
		{ "/petclinic/owners/3/pets/new", JPA_REPO },
		{ "/petclinic/owners/33416/pets/new", JPA_REPO },
	};
	
	@Test
	public void testBasicPartialMappingsForAppScan() {
		PartialMappingDatabase test = PartialMappingsDatabaseFactory.getPartialMappingsDatabase(
				TestUtils.getMappings(petClinicAppScanData), FrameworkType.SPRING_MVC);
		
		test.addMappings(TestUtils.getMappings(petClinicFortifyData));
		
		for (String[] stringArray : springMvcQueries) {
			
			String testDescription = "Path = " + stringArray[0] + ", expected " + stringArray[1];
			PartialMapping result = test.findBestMatch(new DefaultPartialMapping(null, stringArray[0]));
			
			if (result == null) {
				assertTrue("Got null for test " + testDescription, stringArray[1] == null);
			} else {
				assertTrue("Static path was null for " + testDescription, result.getStaticPath() != null);
				assertTrue("Got " + result + " for test " + testDescription, result.getStaticPath().equals(stringArray[1]));
			}
		}
		
	}

}
