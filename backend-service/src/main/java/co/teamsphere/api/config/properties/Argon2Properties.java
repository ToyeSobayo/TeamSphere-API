package co.teamsphere.api.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Data;

@Component
@ConfigurationProperties(prefix = "argon2")
@Data
public class Argon2Properties {
    private int saltLength;
    private int hashLength;
    private int parallelism;
    private int memoryCost;
    private int iterations;
}
