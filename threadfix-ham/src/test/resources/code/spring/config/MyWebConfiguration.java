package code.spring.config;

@Configuration
@EnableWebMvc
@ComponentScan(basePackageClasses = { MyConfiguration.class })
public class MyWebConfiguration {

}