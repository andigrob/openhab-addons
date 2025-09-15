# Meross Binding

This binding integrates **Meross**&reg; devices.

## Supported Things

Supported thing types

- `gateway` : Acts as a Bridge to your Meross cloud account.
- `light` : Represents a light device like a Smart ambient light.
- `garagedoorgeneric` : Meross MSG100 / Garage Door Opener (experimental – realtime state via Meross cloud MQTT; open/close commands not yet implemented)

|   Meross Name        | Type    | Description               | Supported | Tested|
|----------------------|---------|---------------------------|-----------|--------|
| Smart ambient light  | msl430  | Smart ambient light       | yes       | yes    |
| Smart plug           | mss210  | Smart plug                | yes       | yes    |
| Garage Door Opener   | msg100  | Garage door opener (MSG100, experimental: realtime state, no commands yet)| partial  | yes    |

## Discovery

The Discovery service is supported.
If a refresh of devices is needed, e.g. to fetch new devices please disable and re-enable the bridge via the interface button.

## Binding Configuration

To utilize the binding you should first create an account via the Meross Android or iOs app.
Moreover, the devices should be in an online status

## Bridge Configuration

| Name     | Type | Description                                              | Default                    | Required | Advanced |
|----------|------|----------------------------------------------------------|----------------------------|----------|----------|
| hostname | text | Meross Hostname or IP address (for Europe located users) | <https://iotx-eu.meross.com> | yes      | yes      |
| email    | text | Email of your Meross Account                             | N/A                        | yes      | no       |
| password | text | Password of your Meross Account                          | N/A                        | yes      | no       |

### Other host locations

| Location     | Hostname                   |
|--------------|----------------------------|
| Asia-Pacific | <https://iotx-ap.meross.com> |
| US           | <https://iotx-us.meross.com> |

NOTICE: Due to  **Meross**&reg; security policy please minimize host connections in order to avoid TOO MANY TOKENS (code 1301) error occurs which leads to a  8-10 hours suspension of your account.

## Thing Configuration

| Parameter | Type | Description                                                   | Default | Required | Thing type id      | Advanced |
|-----------|------|---------------------------------------------------------------|---------|----------|--------------------|----------|
| lightName | text | The name of the light as registered to Meross account         | N/A     | yes      | light              | no       |
| doorName  | text | The name of the garage door device as registered to the account (garage door support is experimental, commands are not executed yet) | N/A   | yes      | garagedoorgeneric  | no       |

## Channels

| Channel | Thing Types          | Type    | RW   | Description |
|---------|----------------------|---------|------|-------------|
| power   | light / plug types   | Switch  | R/W  | Turn device on/off |
| door    | garagedoorgeneric    | Contact | R    | Garage door state (OPEN/CLOSED) via cloud MQTT (initial GET + PUSH) |
| control | garagedoorgeneric    | String  | W    | Experimental OPEN/CLOSE (cloud MQTT SET, 3s throttle) |

## Security & Rate Limits

TLS: All Meross cloud MQTT connections are forced to TLS (ssl://). If a `tcp://` host is configured it will be transparently upgraded and a warning logged. An internal config flag `allowInsecureTls` exists but defaults to `false` and currently only governs warning verbosity (no plaintext fallback implemented).

Rate Limits: Meross enforces message and token limits. Keep command frequency modest (empirically <150 msgs/hour) to avoid account throttling or temporary suspension.

Credentials & Files: Retrieved cloud credentials and device lists are stored under the openHAB userdata path (e.g. `/var/lib/openhab/meross/`). Protect file system permissions accordingly.

Garage Door State: The MSG100 state is initialized shortly after subscription using a signed GET over MQTT and then kept current by PUSH events. If state remains NULL, enable DEBUG/TRACE logging for the binding to inspect GET/ACK traffic.

Disclaimer: Excessive or abusive cloud usage remains the user's responsibility.

## Full Example

### meross.things

```java
Bridge meross:gateway:mybridge "Meross bridge" [ hostName="https://iotx-eu.meross.com", userEmail="abcde" userPassword="fghij" ] {
    light SC_plug                  "Desk"         [ lightName="Desk" ]
    garagedoorgeneric GD_main      "Main Garage"  [ doorName="Main Garage" ]
}
```

### meross.items

```java
Switch              iSC_plug                 "Desk"                                    { channel="meross:light:mybridge:SC_plug:power" }
String              iGD_main_control         "Garage Control"                           { channel="meross:garagedoorgeneric:mybridge:GD_main:control" }
Contact             iGD_main_state           "Garage State"                              { channel="meross:garagedoorgeneric:mybridge:GD_main:door" }
```

### meross.sitemap Example

```perl
sitemap meross label="Meross Binding Example Sitemap"
{
    Frame label="Living Room"
    {
          Default item=iSC_plug          icon="light"
    }

}
```
