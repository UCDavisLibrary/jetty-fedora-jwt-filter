package edu.ucdavis.library.jetty;

import org.eclipse.jetty.security.Authenticator;
import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.util.component.AbstractLifeCycle;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.UnsupportedEncodingException;
import java.lang.ref.WeakReference;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Jetty authenticator component for container-managed Fedora JWT authentication.
 *
 * @author Justin Merz
 */
public class JwtAuthenticator extends AbstractLifeCycle implements Authenticator {
	
	// env config variables
	private static final String JWT_SECRET = "JWT_SECRET";
	private static final String JWT_ISSUER = "JWT_ISSUER";
	private static final String JWT_COOKIE_NAME = "JWT_COOKIE_NAME";
	private static final String JWT_VERBOSE = "JWT_VERBOSE";
	
    private static final String AUTH_HEADER_KEY = "Authorization";
    // with trailing space to separate token
    private static final String AUTH_HEADER_VALUE_PREFIX = "Bearer "; 
    
    private static final String AUTH_COOKIE_KEY = "fin-jwt";

    /** Name of authentication method provided by this authenticator. */
    public static final String AUTH_METHOD = "JWT";
    
    /** hack to allow env variable based logging changes **/
    public Boolean verbose = false;
    
    /** Session attribute used to cache JWT authentication data. */
    private static final String CACHED_AUTHN_ATTRIBUTE = "edu.ucdavis.library.jetty.Authentication";

    /** Logger instance. */
    private final Logger logger = LoggerFactory.getLogger(JwtAuthenticator.class);

    /** Map of tickets to sessions. */
    private final ConcurrentMap<String, WeakReference<HttpSession>> sessionMap =
            new ConcurrentHashMap<String, WeakReference<HttpSession>>();

    /** JWT ticket parser component. */
    private JwtParser jwtParser = new JwtParser();

    // should be set by config
    /**  who issued token **/
    private String issuer;
    
    // should be set by config
    /** issuer secret **/
    private String secret;
    
    private String cookieKey = null;
    
    private boolean allowAnonymous = true;

	public String getCookieKey() {
		return cookieKey;
	}

	public void setCookieKey(String cookieKey) {
		this.cookieKey = cookieKey;
	}
    
    public String getIssuer() {
		return issuer;
	}


	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}


	public String getSecret() {
		return secret;
	}


	public void setSecret(String secret) {
		this.secret = secret;
	}

	public boolean allowAnonymous() {
		return allowAnonymous;
	}

	public void setAllowAnonymous(boolean allowAnonymous) {
		this.allowAnonymous = allowAnonymous;
	}

    public void setConfiguration(final AuthConfiguration configuration) {
    		// if no user provided cookieKey, set default
    		if( getCookieKey() == null ) setCookieKey(AUTH_COOKIE_KEY);
    		
    		// override config with environmental variables.
    		// makes for easy docker setup
    		Map<String, String> env = System.getenv();
    		if( env.containsKey(JWT_SECRET) && !env.get(JWT_SECRET).equals("") ) {
    			setSecret(env.get(JWT_SECRET));
    		}
    		if( env.containsKey(JWT_ISSUER) && !env.get(JWT_ISSUER).equals("") ) {
    			setIssuer(env.get(JWT_ISSUER));
    		}
    		if( env.containsKey(JWT_COOKIE_NAME) && !env.get(JWT_COOKIE_NAME).equals("") ) {
    			setCookieKey(env.get(JWT_COOKIE_NAME));
    		}

    		if( env.containsKey(JWT_VERBOSE) && !env.get(JWT_VERBOSE).equals("") ) {
    			verbose = true;
    			logger.info("verbose jwt logging enabled");
    		}
    		
    		try {
			jwtParser.init(secret, issuer);
		} catch (IllegalArgumentException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }


    public String getAuthMethod() {
        return AUTH_METHOD;
    }

    public void prepareRequest(final ServletRequest request) {
        // Nothing to do
    }

    public Authentication validateRequest(
            final ServletRequest servletRequest, final ServletResponse servletResponse, final boolean mandatory)
            throws ServerAuthException {

        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        
        JwtAuthentication authentication = null;
        // TODO: Currently this is tied to the JSESSION id, which I don't think we want to use
//        JwtAuthentication authentication = fetchCachedAuthentication(request);
//        if (authentication != null) {
//        		if( verbose ) logger.info("returning cached jwt request");
//            return authentication;
//        }

        String jwt = getBearerToken( request );
        if( verbose ) logger.info("jwt={}", jwt);
        
        if (jwt != null ) {
            try {
                final DecodedJWT decodedJwt = jwtParser.verify(jwt);
                
                if( decodedJwt == null ) {
                    if( verbose ) logger.info("unable to decode jwt, returning unauthenticated");
                    return Authentication.UNAUTHENTICATED;
                }
                
                Claim username = decodedJwt.getClaims().get("username");
                Claim admin = decodedJwt.getClaims().get("admin");
                
                if( username == null ) {
                    if( verbose ) logger.info("no username provided in jwt, returning unauthenticated");
                    return Authentication.UNAUTHENTICATED;
                }
                
                boolean isAdmin = false;
                if( admin != null ) {
                	isAdmin = admin.asBoolean();
                }
                
                if( verbose ) logger.info("jwt username={} isAdmin={}", username.asString(), isAdmin);
                
                JwtPrincipal principle = new JwtPrincipal(username.asString());
                if( isAdmin) principle.setAdmin(true);
                
                authentication = new JwtAuthentication(this, jwt, principle);
                
                // See TODO above
//                cacheAuthentication(request, authentication);
            } catch (Exception e) {
                if( verbose ) {
                    logger.info("JWT ticket validation failed: {}", e.toString());
                    logger.info("JWT Exception info", e);
                    logger.info("returning unauthenticated");
                }
                return Authentication.UNAUTHENTICATED;
                // don't want to do this, sends 500, even if token was just expired
                // throw new ServerAuthException("JWT ticket validation failed", e);
            }
        }
        
        if (authentication != null) {
            return authentication;
        }
        
        if( allowAnonymous() ) {
        		if( verbose ) logger.info("returning anonymous user");
        		JwtPrincipal principle = new JwtPrincipal("anonymous");
        		return new JwtAuthentication(this, "", principle);
        }
        	
        if( verbose ) logger.info("returning unauthenticated");
        return Authentication.UNAUTHENTICATED;        
    }

    public boolean secureResponse(
            final ServletRequest request,
            final ServletResponse response,
            final boolean mandatory,
            final Authentication.User user) throws ServerAuthException {
        return true;
    }

    @Override
    protected void doStart() throws Exception {
        if (jwtParser == null) {
            throw new RuntimeException("JwtParser cannot be null");
        }
    }

    protected void clearCachedAuthentication(final String ticket) {
        final WeakReference<HttpSession> sessionRef = sessionMap.remove(ticket);
        if (sessionRef != null && sessionRef.get() != null) {
            sessionRef.get().removeAttribute(CACHED_AUTHN_ATTRIBUTE);
        }
    }

    private void cacheAuthentication(final HttpServletRequest request, final JwtAuthentication authentication) {
        final HttpSession session = request.getSession(true);
        if (session != null) {
            session.setAttribute(CACHED_AUTHN_ATTRIBUTE, authentication);
            sessionMap.put(authentication.getTicket(), new WeakReference<HttpSession>(session));
        }
    }

    private JwtAuthentication fetchCachedAuthentication(final HttpServletRequest request) {
        final HttpSession session = request.getSession(false);
        if (session != null) {
            return (JwtAuthentication) session.getAttribute(CACHED_AUTHN_ATTRIBUTE);
        }
        return null;
    }
    
    /**
     * Get the bearer token from the HTTP request.
     * The token is in the HTTP request "Authorization" header in the form of: "Bearer [token]"
     */
    private String getBearerToken( HttpServletRequest request ) {
        String authHeader = request.getHeader( AUTH_HEADER_KEY );
        if ( authHeader != null && authHeader.startsWith( AUTH_HEADER_VALUE_PREFIX ) ) {
            return authHeader.substring( AUTH_HEADER_VALUE_PREFIX.length() );
        }
        
        Cookie [] cookies = request.getCookies();
        if( cookies == null ) return null;
        
        for (Cookie cookie : cookies) {
             if (getCookieKey().equals(cookie.getName())) {
                  return cookie.getValue();
             }
        }
        
        return null;
    }

}
