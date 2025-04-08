package co.teamsphere.api.config.properties;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;

@Configuration
@ConfigurationProperties(prefix = "app.environment")
@Data
public class AppProperties {

    private List<String> allowedOrigins;
}
