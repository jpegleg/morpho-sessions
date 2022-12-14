![cdlogo](https://carefuldata.com/images/cdlogo.png)

# morpho-sessions

A rust template for front-end web server microservice container using actix web framework.

The index.html in the template is to include a form field that allows the "fage" query to be sent with a GET using an integer value.

Example:

```
<form action="/session">
  <h1>Age Required</h1>
  <label for="fage">Enter your age in years:</label><br>
  </br>
  <input type="number" required="required" id="fage" name="fage" min="1" max="200"></br>
  </br>
  <input type="submit" value="enter">
  </br>
</form> 
```

The `type="number"` and `required="required"` are important to do form input validation. If a user bypasses the form and sends non-integer data into the query, they will observe deserialization errors.

#### Also see the more "core" version without session cookies: https://github.com/jpegleg/morpho-web/

The included Dockerfile uses the `FROM ekidd/rust-musl-builder AS build` to compile with cargo
and then we copy the dependencies into a `FROM scratch` empty container. The resulting OCI
image has no shell, nothing but the dependencies for the web server.

The base image of the core is less than 12MB and just over 12MB with the cookies code, for the entire framework.
Unlike the regular morpho-web, we don't copy any local files into the build, the /app/static directory is volume
mount containing the content to load. The key and cert for TLS are also mounted.

From the test docker-compose.yml:

```
    volumes:
      - /opt/protean-gitops/static/:/app/static/
      - /opt/protean-gitops/cert.pem:/app/cert.pem
      - /opt/protean-gitops/privkey.pem:/app/privkey.pem
```

In production, rather than using Docker, we can use Kubernetes and mount those more appropriately.
The purpose of the docker-compose.yml and the protean references are for some testing systems usage.

## rustls for HTTPS

This program uses rustls for TLS, leveraging the strong defaults. It includes support for TLSv1.2 and TLSv1.3 only,
with weak features disabled. The downside of rustls is that it doesn't have a wide of a range of feature support as openssl,
although is very correct and performant and should ideally be adopted when possible.

## tokio async io

We can serve a lot of requests with actix use of tokio async io, letting IO-bound workloads scale very well.
The reading of files from the filesystem is not special in terms of performance, peforming much like other
web servers. The performance is very good and reliable.

## cloud native design

This web server template is cloud native, working well in Kubernetes and Docker, etc.
It works well with many replicas, has a minimized set of dependencies and libraries,
and puts security as a priority.

## redirecting to HTTPS

Port redirection is included by default now.

## security headers

HSTS and security headers are inserted by default.

## the cookies in the template

The default cookie is not a secured (signed) cookie, just a simple session cookie. Actix has support for adding signing and other aspects to cookies if desired. The designed usage is not for sensitive sessions, however it can be adjusted to the needs of more sensitive sessions.

## session files

The template expects index.html to be an (HTML) form for entering visitor (age) value. This type of thing is not a strong control, but legally required in some areas for certain types of commerce.

index.html - the form page
index2.html - the actual index page
index3.html - the warning page

Feel free to adjust those file names, they don't have to be html, etc.

## TODO

- error handling for the session counter
