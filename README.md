# jetty-fedora-jwt-filter
JWT based authentication for Jetty.  User roles are specific to Fedora Commons Repository.

## Required Jars

Most jars are available via Maven.  Others I have stuck in here in the /lib directory and
need to figure out a better place to store them.

## Installing required JARs

All required jars should be placed in ${jetty.home}/lib/ext.  The jars will then be assable to the 
auth plugin.

## Wiring up to jetty

This uses Jetty's standard auth mechanism.  This means you don't need to modify a the Fedora
WAR file to use.  Simply deploy your war to ${jetty.home}/webapps then name the following xml
file with the same name as your war.  This example will assume you have called your file *fcrepo.war*

#### fcrepo.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Configure PUBLIC "-//Jetty//Configure//EN" "http://www.eclipse.org/jetty/configure.dtd">

<Configure id="fcrepo" class="org.eclipse.jetty.webapp.WebAppContext">
  <!-- sets context root to '/' so no /fcrepo -->
  <Set name="contextPath">/</Set>
  <!-- TODO: you can use a jetty.base xml element here, need to swap in -->
  <Set name="war">/var/lib/jetty/webapps/fcrepo.war</Set>

  <Get name="securityHandler">
    <Set name="authenticator">
      <New class="edu.ucdavis.library.jetty.JwtAuthenticator">
        <!-- Required -->
        <!-- This is based on what you used to sign the JWT -->
        <Set name="secret">[[your secret key here]]</Set>
        <Set name="issuer">[[your domain here: eg library.ucdavis.edu]]</Set>
        <!-- Optional -->
        <!--
            defaults to true
            <Set name="allowAnonymous">false</Set>
        -->
        <!--
            cookie name to use for cookie based auth.
            note: this comes with the usual cookie based security risks
            <Set name="cookieKey">someOtherKey</Set>
        -->
      </New>
    </Set>
  </Get>
</Configure>
```