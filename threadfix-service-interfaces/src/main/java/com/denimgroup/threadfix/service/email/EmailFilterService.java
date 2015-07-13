package com.denimgroup.threadfix.service.email;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import static com.denimgroup.threadfix.CollectionUtils.set;
import static com.denimgroup.threadfix.CollectionUtils.list;

import com.denimgroup.threadfix.logging.SanitizedLogger;

//Bean is instantiated in the EmailServicesSetup
public class EmailFilterService {

	private final SanitizedLogger log = new SanitizedLogger(EmailFilterService.class);

	private List<String> regexFilters = null;

	public boolean validateEmailAddress(String emailAddress){
		if (regexFilters==null){
			return true;
		}
		for (String regexFilter : regexFilters){
			if (emailAddress.matches(regexFilter)){
				return true;
			}
		}
		return false;
	}

	public Set<String> getFilteredEmailAddresses(List<String> emailAddresses){
		Set<String> filteredEmailAddresses = set();
		for (String emailAddress : emailAddresses){
			if(validateEmailAddress(emailAddress)){
				filteredEmailAddresses.add(emailAddress);
			} else {
				log.warn("Blocked an email address not matching current filters: " + emailAddress);
			}
		}
		return filteredEmailAddresses;
	}

	public List<String> getBlockedEmailAddresses(List<String> emailAddresses){
		List<String> blockedEmailAddresses = list();
		for (String emailAddress : emailAddresses){
			if(!validateEmailAddress(emailAddress)){
				blockedEmailAddresses.add(emailAddress);
			}
		}
		return blockedEmailAddresses;
	}

	public void parseFilters(String filterString){
		this.regexFilters = list();
		String[] wildcardFilters = filterString.split(",");
		for (int i=0; i < wildcardFilters.length; i++){
			String wildcardFilter = wildcardFilters[i];
			String[] splittedCard = wildcardFilter.split("\\*");
			String regexFilter = "";
			for (int j=0; j<splittedCard.length-1; j++){ //doesn't enter in the loop if no *
				if (!splittedCard[j].isEmpty()){
					regexFilter+=Pattern.quote(splittedCard[j]);
				}
				regexFilter+=".*";
			}
			regexFilter+=Pattern.quote(splittedCard[splittedCard.length-1]);
			if(wildcardFilter.endsWith("*")){
				regexFilter+=".*";
			}
			regexFilters.add(regexFilter);
		}
		log.info("Set the following email filters during configuration: " + regexFilters.toString());
	}
}
