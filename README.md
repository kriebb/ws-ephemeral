# WS-EPHEMERAL

> [!CAUTION]
> Please use this tool responsibly. Excessive or inappropriate
> usage may result in temporary suspension of your account. Due to lack of
> time I will try to revisit sometime in future but I strongly advice to let
> it run at default pace, that is once every week. For new user cookie generation
> might fail at the beginning, please try again after some time once you delete
> partially created cookie.

This project aims to automate setting up ephemeral port on Windscribe VPN
service for the purpose of port forwarding. Once the setup is done it wait
patiently for next seven days. It delete the ephemeral port setting if any and
set the new one. Useful for some torrent application which are running behind
Windscribe VPN and need to open the ports.

## Docker Setup

> [!important]
> NOTE: V1 is deprecated and should not be used.

### Registries

Only ghcr.io is currently used for the Docker registry:

- ghcr.io/kriebb/ws-ephemeral

### Tags

Available tags for docker image (based on semver):

| Tag    | Container Type                 |
| ------ | ------------------------------ |
| main   | straight from `main` branch    |
| latest | latest stable released version |
| x      | specific major version         |
| x.x.x  | specific version               |

### Deploy

#### Cli

```bash
docker run \
-e ONESHOT=false \
-e QBIT_HOST=http://192.168.1.10 \
-e QBIT_PASSWORD=password \
-e QBIT_PORT=8080 \
-e QBIT_PRIVATE_TRACKER=true \
-e QBIT_USERNAME=username \
-e REQUEST_TIMEOUT=10 \
-e WS_COOKIE_PATH=/cookie \
-e WS_DEBUG=False \
-e WS_PASSWORD=password \
-e WS_USERNAME=username \
-e WS_TOPT=totp_token \
-v /path/to/local/data:/cookie \
ghcr.io/kriebb/ws-ephemeral:latest
```

#### Docker-compose

Docker compose file is provided for example, make some adjustment and run as,

```bash
docker compose up -d
```

#### Health Check

The container includes a built-in health check script (`healthcheck.py`) that verifies the presence of the session cookie and connectivity to qBittorrent. You can enable it in your `docker-compose.yaml` as follows:

```yaml
    healthcheck:
      test: ["CMD", "python3", "healthcheck.py"]
      interval: 1h
      timeout: 10s
      retries: 3
```

### Environment Variables

| Variable             | Comment                                                                          |
| -------------------- | -------------------------------------------------------------------------------- |
| WS_USERNAME          | WS username                                                                      |
| WS_PASSWORD          | WS password                                                                      |
| WS_TOTP              | WS totp token for 2fa                                                            |
| WS_DEBUG             | Enable Debug logging                                                             |
| WS_COOKIE_PATH       | Persistent location for the cookie. (v3.x.x only)                                |
| QBIT_USERNAME        | QBIT username                                                                    |
| QBIT_PASSWORD        | QBIT password                                                                    |
| QBIT_HOST            | QBIT web address like, https://qbit.xyz.com or http://192.168.1.10               |
| QBIT_PORT            | QBIT web port number like, 443 or 8080                                           |
| QBIT_PRIVATE_TRACKER | get QBIT ready for private tracker by disabling dht, pex and lsd (true or false) |
| ONESHOT              | Run and setup the code only one time so that job can be schedule externally      |
| REQUEST_TIMEOUT      | configurable http api timeout for slow network/busy websites                     |
| RE_CSRF_TIME         | Regex pattern for extracting CSRF time. Default: `csrf_time = (?P<ctime>\d+)`     |
| RE_CSRF_TOKEN        | Regex pattern for extracting CSRF token (JS style). Default: `csrf_token = \'(?P<ctoken>\w+)\'` |
| RE_META_CSRF_TOKEN   | Regex pattern for extracting CSRF token (meta tag style). Default: `<meta name="csrf-token" content="(?P<ctoken>[^"]+)"` |

> [!tip]
> **Customizing CSRF Regex Patterns**
>
> If Windscribe's website structure changes, leading to errors in token extraction, you can update the `RE_CSRF_TIME`, `RE_CSRF_TOKEN`, or `RE_META_CSRF_TOKEN` environment variables. To find the correct pattern, inspect the Windscribe login page HTML (e.g., by right-clicking and selecting "Inspect" or "View Page Source" in your browser) and search for elements related to "csrf_time" or "csrf-token". The `renew_csrf` function also logs the first 500 characters of the HTML response at debug level if a token isn't found, which can aid in debugging.

> [!tip]
> NOTE: for usage see [Docker Setup](#docker-setup) v2 setup guide.

## Unraid Setup

Unraid template is now available under community application.

## Changelog

Located [here](./CHANGELOG.md)

## Privacy

I assure you that nothing is being collected or logged. Your credentials are
safe and set via environment variable only. Still If you have further questions
or concerns, please open an issue here.

## Roadmap

- [x] Support 2FA, #19
- [x] Robust CSRF handling
  - [x] Auto-login on session expiry
  - [x] Configurable Regex via Environment Variables
  - [x] Fallback mechanisms for token extraction
- [x] CI/CD Automation
  - [x] Automated Semantic Release (versioning & changelog)
  - [x] Docker build & push to GHCR (ghcr.io only)
- [ ] Daemon mode and job mode
  - [ ] Rest API (useful for cron/script job)
  - [ ] Separate port renewal, qbittorrent update and private tracker logic
  - [ ] Random job time for cron job #15
- [ ] Allow to run custom script (for now Bash script only) #12
- [ ] Support for deluge
- [ ] Gluetun support [#2392](https://github.com/qdm12/gluetun/pull/2392)

## License

[GPL3](LICENSE.md)
