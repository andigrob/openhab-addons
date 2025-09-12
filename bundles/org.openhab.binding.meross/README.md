# Meross Binding

This binding integrates **Meross**&reg; devices

## Supported Things

Supported thing types

- `gateway` : Acts as a Bridge to your Meross cloud account.
- `light` : Represents a light device like a Smart ambient light.
- `garagedoorgeneric` : Meross MSG100 / Garage Door Opener (EXPERIMENTAL, HTTP-only – commands are placeholders, no state polling yet)

|   Meross Name        | Type    | Description               | Supported | Tested|
|----------------------|---------|---------------------------|-----------|--------|
| Smart ambient light  | msl430  | Smart ambient light       | yes       | yes    |
| Smart plug           | mss210  | Smart plug                | yes       | yes    |
| Garage Door Opener   | msg100  | Garage door opener (MSG100, experimental HTTP-only, limited)| partial  | no     |

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

Channels:

| Channel | Type   | Read/Write | Description                                                          |
|---------|--------|------------|----------------------------------------------------------------------|
| power   | Switch | N/A        | Power bulb/plug capability to control bulbs and plugs on/off         |
| door    | Contact| Read       | (Planned) Garage door state (OPEN/CLOSED) – not implemented yet       |
| control | String | Write      | (Placeholder) Intended OPEN/CLOSE commands (no effect in HTTP-only mode) |

NOTICE: Due to **Meross**&reg; security policy please limit communication to no more than 150 messages every one hour at the earliest convenience otherwise, the user is emailed by Meross of the limit exceed and if such a behaviour does not change the user's account will be **BANNED**!

The inappropriate usage is user's responsibility

NOTICE: Due to the above mentioned security policy  currently is not possible to get the device on/off status  

## Full Example

### meross.things

```java
Bridge meross:gateway:mybridge "Meross bridge" [ hostName="https://iotx-eu.meross.com", userEmail="abcde" userPassword="fghij" ] {
    light SC_plug                  "Desk"         [lightName="Desk"]
    // Garage door support is experimental (no real open/close yet)
    garagedoorgeneric GD_main      "Main Garage"  [doorName="Main Garage"]
}
```

### meross.items

```java
Switch              iSC_plug                 "Desk"                                    { channel="meross:light:mybridge:SC_plug:power" }
String              iGD_main_control         "Garage Control (placeholder)"             { channel="meross:garagedoorgeneric:mybridge:GD_main:control" }
Contact             iGD_main_state           "Garage State (planned)"                   { channel="meross:garagedoorgeneric:mybridge:GD_main:door" }
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
