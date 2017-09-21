package edu.ucdavis.library.jetty;

import org.eclipse.jetty.server.UserIdentity;

import javax.security.auth.Subject;
import java.security.Principal;

/**
 * JWT user identity backed by principal data.
 *
 * @author Justin Merz
 */
public class JwtUserIdentity implements UserIdentity {

    private JwtPrincipal principal;

    /**
     * Creates a new instance from a JWT principal.
     *
     * @param principal JwtPrincipal resulting from successful jwt validation.
     */
    public JwtUserIdentity(final JwtPrincipal principal) {
        this.principal = principal;
    }

    public Subject getSubject() {
        final Subject subject = new Subject();
        subject.getPrincipals().add(principal);
        return subject;
    }

    public Principal getUserPrincipal() {
        return principal;
    }

    public boolean isUserInRole(final String role, final Scope scope) {
    		if( role.equals("fedoraAdmin") && principal.isAdmin() ) {
    			return true;
    		} else if( role.equals("fedoraUser") ) {
    			return true;
    		}
        return false;
    }

    @Override
    public String toString() {
        return principal.getName();
    }
}