package sample.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * This class creates authorities for each role from the JWT.
 * This is adapted from a Stack Overflow answer: https://stackoverflow.com/a/58234971
 *
 * In our case, the "resourceId" is the client ID.  If you need realm roles, use "account".
 *
 * Note that this works for both user and service account JWTs (as long as the service accounts
 * have client roles associated with them in Keycloak).
 */
public class CustomJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken>
{
    private static Collection<? extends GrantedAuthority> extractResourceRoles(final Jwt jwt, final String resourceId)
    {
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        Map<String, Object> resource;
        Collection<String> resourceRoles;
        if (resourceAccess != null && (resource = (Map<String, Object>) resourceAccess.get(resourceId)) != null &&
                (resourceRoles = (Collection<String>) resource.get("roles")) != null)
            return resourceRoles.stream()
                    .map(x -> new SimpleGrantedAuthority("ROLE_" + x))
                    .collect(Collectors.toSet());
        return Collections.emptySet();
    }

    private final JwtGrantedAuthoritiesConverter defaultGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    private final String resourceId;

    public CustomJwtAuthenticationConverter(String resourceId)
    {
        this.resourceId = resourceId;
    }

    @Override
    public AbstractAuthenticationToken convert(final Jwt source)
    {
        Collection<GrantedAuthority> authorities = Stream.concat(defaultGrantedAuthoritiesConverter.convert(source)
                        .stream(),
                extractResourceRoles(source, resourceId).stream())
                .collect(Collectors.toSet());
        return new JwtAuthenticationToken(source, authorities);
    }
}