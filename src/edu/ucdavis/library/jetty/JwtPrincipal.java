package edu.ucdavis.library.jetty;

import java.security.Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JwtPrincipal implements Principal {
	
	private String name;
	private boolean isAdmin;
	
	public JwtPrincipal(String name) {
		this.name = name;
	}
	
	public String getName() {
		return name;
	}
	
    public String toString() {
        return getName();
    }

    public boolean equals(final Object o) {
        if (o == null) {
            return false;
        } else if (!(o instanceof JwtPrincipal)) {
            return false;
        } else {
            return getName().equals(((JwtPrincipal) o).getName());
        }
    }

    public int hashCode() {
        return 37 * getName().hashCode();
    }

	public boolean isAdmin() {
		return isAdmin;
	}

	public void setAdmin(boolean isAdmin) {
		this.isAdmin = isAdmin;
	}
}
