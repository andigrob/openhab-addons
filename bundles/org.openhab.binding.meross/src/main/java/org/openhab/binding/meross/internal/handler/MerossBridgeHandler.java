/*
 * Copyright (c) 2010-2025 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.openhab.binding.meross.internal.handler;

import java.io.File;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.openhab.binding.meross.internal.mqtt.MerossMqttConnector;
import org.openhab.binding.meross.internal.mqtt.MerossMqttListener;
import java.net.ConnectException;
import java.util.Collection;
import java.util.Set;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.binding.meross.internal.api.MerossHttpConnector;
import org.openhab.binding.meross.internal.config.MerossBridgeConfiguration;
import org.openhab.binding.meross.internal.discovery.MerossDiscoveryService;
import org.openhab.binding.meross.internal.dto.HttpConnectorBuilder;
import org.openhab.binding.meross.internal.exception.MerossApiException;
import org.openhab.core.OpenHAB;
import org.openhab.core.thing.Bridge;
import org.openhab.core.thing.ChannelUID;
import org.openhab.core.thing.Thing;
import org.openhab.core.thing.ThingStatus;
import org.openhab.core.thing.ThingStatusDetail;
import org.openhab.core.thing.binding.BaseBridgeHandler;
import org.openhab.core.thing.binding.ThingHandlerService;
import org.openhab.core.types.Command;

/**
 * The {@link MerossBridgeHandler} is responsible for handling http communication with and retrieve data from Meross
 * Host.
 *
 * @author Giovanni Fabiani - Initial contribution
 */
@NonNullByDefault
public class MerossBridgeHandler extends BaseBridgeHandler implements MerossMqttListener {
    private MerossBridgeConfiguration config = new MerossBridgeConfiguration();
    private @Nullable MerossHttpConnector merossHttpConnector;
    private final Logger logger = LoggerFactory.getLogger(MerossBridgeHandler.class);
    private @Nullable MerossMqttConnector mqttConnector;
    private static final String CREDENTIAL_FILE_NAME = "meross" + File.separator + "meross_credentials.json";
    private static final String DEVICE_FILE_NAME = "meross" + File.separator + "meross_devices.json";
    public static final File CREDENTIALFILE = new File(
            OpenHAB.getUserDataFolder() + File.separator + CREDENTIAL_FILE_NAME);
    public static final File DEVICE_FILE = new File(OpenHAB.getUserDataFolder() + File.separator + DEVICE_FILE_NAME);

    public MerossBridgeHandler(Thing thing) {
        super((Bridge) thing);
    }

    @Override
    public void initialize() {
        config = getConfigAs(MerossBridgeConfiguration.class);

        if (config.hostName.isBlank() || config.userEmail.isBlank() || config.userPassword.isBlank()) {
            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR);
            return;
        }

        MerossHttpConnector merossHttpConnectorLocal = merossHttpConnector = HttpConnectorBuilder.newBuilder()
                .setApiBaseUrl(config.hostName).setUserEmail(config.userEmail).setUserPassword(config.userPassword)
                .setCredentialFile(CREDENTIALFILE).setDeviceFile(DEVICE_FILE).build();

        if (merossHttpConnectorLocal == null) {
            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.COMMUNICATION_ERROR);
            return;
        }
        try {
            // Always fetch data first (credentials + devices). Ensures credentials file exists for MQTT domain.
            merossHttpConnectorLocal.fetchDataAsync();

            if (config.enableMqtt) {
                startMqttAsync(merossHttpConnectorLocal);
            } else {
                logger.debug("Meross MQTT disabled via configuration.");
            }
            updateStatus(ThingStatus.ONLINE);
        } catch (ConnectException | MerossApiException e) {
            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.COMMUNICATION_ERROR, e.getMessage());
        }
    }

    @Override
    public void handleCommand(ChannelUID channelUID, Command command) {
    }

    @Override
    public Collection<Class<? extends ThingHandlerService>> getServices() {
        return Set.of(MerossDiscoveryService.class);
    }

    public @Nullable MerossHttpConnector getMerossHttpConnector() {
        return merossHttpConnector;
    }

    public boolean isMqttEnabled() {
        return config.enableMqtt;
    }

    public @Nullable MerossMqttConnector getMqttConnector() {
        return mqttConnector;
    }

    // --- MerossMqttListener ---
    @Override
    public void onMessage(@Nullable String deviceUuid, String topic, byte[] payload) {
        if (logger.isTraceEnabled()) {
            String snippet = new String(payload, 0, Math.min(payload.length, 200));
            logger.trace("MQTT RX topic={} bytes={} snippet={}", topic, payload.length, snippet);
        }
        // Future: parse JSON, update thing/channel states
    }

    private String sanitizeHost(String host) {
        String h = host.trim();
        if (h.startsWith("https://")) {
            h = h.substring(8);
        } else if (h.startsWith("http://")) {
            h = h.substring(7);
        }
        // remove any leading // if present
        while (h.startsWith("//")) {
            h = h.substring(2);
        }
        // strip trailing slashes
        while (h.endsWith("/")) {
            h = h.substring(0, h.length() - 1);
        }
        return h;
    }

    private void startMqttAsync(MerossHttpConnector httpConnector) {
        scheduler.execute(() -> {
            try {
                var creds = httpConnector.readCredentials();
                int attempts = 0;
                while (creds == null && attempts < 5) { // wait up to ~5 * 2s = 10s
                    attempts++;
                    logger.debug("Waiting for Meross credentials (attempt {}/{})", attempts, 5);
                    Thread.sleep(2000);
                    creds = httpConnector.readCredentials();
                }
                if (creds == null) {
                    logger.debug("Credentials not available after wait window; skipping MQTT startup");
                    return;
                }
                String candidate = config.mqttHost.isBlank() ? (creds.mqttDomain() != null && !creds.mqttDomain().isBlank()
                        ? creds.mqttDomain() : config.hostName) : config.mqttHost;
                String sanitized = sanitizeHost(candidate);
                mqttConnector = new MerossMqttConnector(sanitized);
                mqttConnector.authenticate(creds.userId(), creds.key(), creds.token());
                logger.debug(
                        "Meross MQTT enabled (async connect) rawHost={} sanitized={} credsDomain={} explicitHostProvided={} credsPreloaded=true",
                        candidate, sanitized, creds.mqttDomain(), !config.mqttHost.isBlank());
                MerossMqttConnector connectorRef = mqttConnector;
                connectorRef.connect();
                if (connectorRef.isConnected()) {
                    var devices = httpConnector.readDevices();
                    if (devices != null && !devices.isEmpty()) {
                        var topics = devices.stream().map(d -> "/appliance/" + d.uuid() + "/subscribe").distinct().toList();
                        connectorRef.addListener(this);
                        connectorRef.subscribe(topics);
                        logger.info("Subscribed to {} Meross device topics", topics.size());
                    } else {
                        logger.debug("No devices available for MQTT subscription yet");
                    }
                }
            } catch (Exception e) {
                logger.debug("MQTT startup failed: {}", e.getMessage());
            }
        });
    }
}
