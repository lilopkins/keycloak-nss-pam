# Keycloak NSS/PAM Modules

## Building

To build these modules, use cross. This will ensure that a suitable
environment is available:

```sh
$ cross build
```

## Installing

```sh
$ cp pam_keycloak.so /lib/x86_64-linux-gnu/security
$ install -m 0644 libnss_keycloak.so.2 /lib/x86_64-linux-gnu
$ ldconfig
```
