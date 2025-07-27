# Keycloak NSS/PAM Modules

## Building

To build these modules, use cross. This will ensure that a suitable
environment is available:

```sh
$ cross build
```

## Keycloak Config

Note: this needs expanding properly, but those familar with Keycloak may
be able to follow these notes.

- Add a client for the NSS/PAM services
  - Give it "Direct access grants" and "Service accounts roles"
  - If desired, you can change the direct grant flow to add RBAC through
    a realm role
- In "Realm settings" > "User profile", create an attribute for the Unix
  UID. The name of this attribute should be the `uid_attribute_id` in
  the configuration TOML.
- Create a client scope for the UID
  - These options work well:
    - Type: Optional
    - Display on consent screen: no
    - Include in token scope: yes
  - If you have made an RBAC role, limit the client scope to this role
  - Add a "User Attribute" mapper
    - Map the user attribute to a token claim. The token claim name
      should be the `uid_token_claim` in the configuration TOML.
- Add the client scope to the client, type default.


## Installing

```sh
$ cp pam_keycloak.so /lib/x86_64-linux-gnu/security
$ install -m 0644 libnss_keycloak.so.2 /lib/x86_64-linux-gnu
$ ldconfig
```

Then in `/etc/pam.d/common-auth`, change `pam-unix.so`'s `success=2`,
add after `pam-unix.so`:

```
auth [success=1, default=ignore] pam_keycloak.so
```

In `/etc/pam.d/common-account`:

```
account [success=1, default=ignore] pam_keycloak.so
```

In `/etc/pam.d/common-session`:

```
session required pam_keycloak.so
```
