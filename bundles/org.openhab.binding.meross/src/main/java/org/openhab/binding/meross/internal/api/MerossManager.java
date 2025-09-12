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
package org.openhab.binding.meross.internal.api;

import java.io.IOException;
import java.util.HashSet;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
// MQTT functionality removed (Option B) – class retained for potential future MQTT reintroduction without dependency bloat
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The {@link MerossManager} class is responsible for implementing general functionalities to interact with
 * appliances
 *
 * @author Giovanni Fabiani - Initial contribution
 */
@NonNullByDefault
public class MerossManager {
    private final Logger logger = LoggerFactory.getLogger(MerossManager.class);

    public static MerossManager newMerossManager(MerossHttpConnector merossHttpConnector) {
        return new MerossManager(merossHttpConnector);
    }

    final MerossHttpConnector merossHttpConnector;

    private MerossManager(MerossHttpConnector merossHttpConnector) {
        this.merossHttpConnector = merossHttpConnector;
    }


    /**
     * @param deviceName The device name
     * @param commandType The command type
     * @param commandMode The command Mode
     */

    public void sendCommand(String deviceName, String commandType, String commandMode) throws IOException {
        logger.debug("MQTT sendCommand skipped (disabled) type={} mode={} device={}", commandType, commandMode,
                deviceName);
    }

    public int onlineStatus(String deviceName) throws IOException {
        // Approximate: If device name resolves to UUID via HTTP device list, treat as ONLINE
        String uuid = merossHttpConnector.getDevUUIDByDevName(deviceName);
        return uuid.isEmpty() ? MerossEnum.OnlineStatus.OFFLINE.value() : MerossEnum.OnlineStatus.ONLINE.value();
    }

    public String getSystemAll(String deviceName) throws IOException {
        return ""; // Not available without MQTT
    }

    @Nullable
    public HashSet<String> getAbilities(String deviceName) throws IOException {
        return new HashSet<>(); // Not retrieved without MQTT
    }
}
