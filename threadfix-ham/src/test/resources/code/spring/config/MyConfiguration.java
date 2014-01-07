package code.spring.config;

@Configuration
@EnableWebMvc
@ComponentScan(basePackageClasses = { MyConfiguration.class })
public class MyConfiguration extends WebMvcConfigurerAdapter {

    @Override
    public void addFormatters(FormatterRegistry formatterRegistry) {
        formatterRegistry.addConverter(new MyConverter());
    }

    @Override
    public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
        converters.add(new MyHttpMessageConverter());
    }

    // More overridden methods ...
}