package com.cities.controller;

import java.io.IOException;
import java.util.List;

import org.apache.lucene.queryParser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import com.cities.dao.CityTextIndexDao;
import com.cities.model.City;
import com.cities.repository.CityRepository;
import com.cities.service.CityService;


@Controller
@RequestMapping
public class CityController {
	private static final Logger logger = LoggerFactory.getLogger(CityController.class);
	
	private CityRepository cityRepository;
	private CityTextIndexDao cityTextIndexDao;
	private CityService cityService;
	
	@Autowired
	public void setCityRepository(CityRepository cityRepository) {
		this.cityRepository = cityRepository;
	}
	
	@Autowired
	public void setCityDao(CityTextIndexDao cityDao) {
		this.cityTextIndexDao = cityDao;
	}
	
	@Autowired
	public void setCityService(CityService cityService) {
		this.cityService = cityService;
	}

	// 50 größte Städte auslesen
	@RequestMapping(method=RequestMethod.GET, value="/")
	public ModelAndView showCities() {

		// PageRequest ist für Paginierung gedacht, wird hier aber als LIMIT genutzt
		List<City> cities = cityRepository.getCities(new PageRequest(0, 50));
		
		logger.info("Insgesamt sind " + cities.size() + " Städte vorhanden");
		logger.info("Name der größten Stadt ist " + cities.get(0).getName());
		
		return cityService.buildListView(cities);
	}
	
	// Neue Stadt anlegen
	@RequestMapping(method=RequestMethod.POST, value="/city/add")
	public String addCity(@ModelAttribute("city") City city, BindingResult result) {
		logger.info("Lege neue Stadt " + city.getName() + " an");
		
		cityRepository.save(city);
		
		return "redirect:/";
	}
	
	/* 
	 * Löschen per URL und via AJAX
	 * Ergänzender Hinweis: Lösch-Requests müssen natürlich in der Praxis abgesichert
	 * werden, da sonst jeder User bei bekannter ID des Datensatzes alles löschen kann. 
	 * Das gilt genauso für die Ausführung von Schreibzugriffen.
	 */
	@RequestMapping(method=RequestMethod.GET, value="/city/delete/{id}")
	public String deleteCity(@PathVariable("id") long id) {
		logger.info("Lösche Datensatz " + id);
		
		cityRepository.delete(id);
		
		return "redirect:/";
	}
	
	// Normale Suchfunktion GET
	@RequestMapping(method=RequestMethod.GET, value="/city/search")
	public ModelAndView getSearchResult(@RequestParam("term") String term) {		
		List<City> cities = cityRepository.searchCity(term);
		logger.info("Es wurden " + cities.size() + " Städte gefunden");

		return cityService.buildListView(cities);
	}
	
	// Suchfunktion Autocomplete POST
	@RequestMapping(method=RequestMethod.POST, value="/city/search")
	public ResponseEntity<String> getAutocompleteResult(@RequestParam("term") String term) throws IOException, ParseException {		
		
		// Neue Response-Header nötig, da Ergebnis sonst ISO-codiert
		HttpHeaders responseHeaders = new HttpHeaders();
		responseHeaders.add("Content-Type", "text/html; charset=utf-8");
		
		List<String> cities = cityRepository.searchCityNames(term);
		
		if(cities.size() > 0) {
			logger.info("Es wurden " + cities.size() + " Städte gefunden - Autocomplete");
		} else {
			cities = cityTextIndexDao.searchSimilarCities(term);
		}
		String json = cityService.convertJson(cities);
		return new ResponseEntity<String>(json, responseHeaders, HttpStatus.CREATED);
	}
	
	// Index neu erstellen
	@RequestMapping(method=RequestMethod.GET, value="/createsearchindex")
	public String createSearchIndex() throws InterruptedException {
		logger.info("Schreibe den Lucene-Index neu");
		
		cityTextIndexDao.createSearchIndex();
		
		return "redirect:/";
	}
}
