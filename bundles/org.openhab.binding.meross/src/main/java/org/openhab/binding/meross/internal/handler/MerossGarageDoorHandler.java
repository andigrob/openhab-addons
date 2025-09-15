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

import static org.openhab.binding.meross.internal.MerossBindingConstants.*;

import java.io.IOException;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.binding.meross.internal.api.MerossEnum;
import org.openhab.binding.meross.internal.api.MerossManager;
import org.openhab.binding.meross.internal.config.MerossGarageDoorConfiguration;
import org.openhab.core.library.types.OpenClosedType;
import org.openhab.core.library.types.StringType;
import org.openhab.core.thing.Bridge;
import org.openhab.core.thing.ChannelUID;
import org.openhab.core.thing.Thing;
import org.openhab.core.thing.ThingStatus;
import org.openhab.core.thing.ThingStatusDetail;
import org.openhab.core.thing.ThingStatusInfo;
import org.openhab.core.thing.binding.BaseThingHandler;
import org.openhab.core.types.Command;
import org.openhab.core.types.RefreshType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handler for Meross MSG100 garage door opener.
 *
 * NOTE: Current implementation provides basic OPEN/CLOSE control without state polling (Meross cloud does not easily
 * expose push updates here in current binding). State channel will remain UNKNOWN after refresh as placeholder for
 * future implementation.
 */
@NonNullByDefault
public class MerossGarageDoorHandler extends BaseThingHandler {
    private final Logger logger = LoggerFactory.getLogger(MerossGarageDoorHandler.class);
    private MerossGarageDoorConfiguration config = new MerossGarageDoorConfiguration();
    private @Nullable MerossBridgeHandler merossBridgeHandler;

    public MerossGarageDoorHandler(Thing thing) {
        super(thing);
    }

    @Override
    public void initialize() {
        Bridge bridge = getBridge();
        if (bridge == null || !(bridge.getHandler() instanceof MerossBridgeHandler merossBridgeHandler)) {
            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.BRIDGE_OFFLINE);
            return;
        }
        this.merossBridgeHandler = merossBridgeHandler;
        var merossHttpConnector = merossBridgeHandler.getMerossHttpConnector();
        if (merossHttpConnector == null) {
            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.BRIDGE_OFFLINE);
            return;
        }
        config = getConfigAs(MerossGarageDoorConfiguration.class);
        if (config.doorName.isBlank()) {
            String label = getThing().getLabel();
            if (label != null) {
                config.doorName = label;
            }
        }
        try {
            String deviceUUID = merossHttpConnector.getDevUUIDByDevName(config.doorName);
            if (deviceUUID.isEmpty()) {
                updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR,
                        "No device found with name " + config.doorName);
                return;
            }
            var manager = MerossManager.newMerossManager(merossHttpConnector);
            int status = manager.onlineStatus(config.doorName);
            if (status == MerossEnum.OnlineStatus.ONLINE.value()) {
                updateStatus(ThingStatus.ONLINE);
            } else {
                updateStatus(ThingStatus.OFFLINE);
            }
        } catch (IOException e) {
            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.COMMUNICATION_ERROR, e.getMessage());
        }
    }

    @Override
    public void bridgeStatusChanged(ThingStatusInfo bridgeStatusInfo) {
        if (bridgeStatusInfo.getStatus() == ThingStatus.ONLINE) {
            updateStatus(ThingStatus.ONLINE);
        } else {
            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.BRIDGE_OFFLINE);
        }
    }

    @Override
    public void handleCommand(ChannelUID channelUID, Command command) {
        if (thing.getStatus() != ThingStatus.ONLINE) {
            return;
        }
        MerossBridgeHandler bridgeHandler = this.merossBridgeHandler;
        if (bridgeHandler == null) {
            return;
        }
        var merossHttpConnector = bridgeHandler.getMerossHttpConnector();
        if (merossHttpConnector == null) {
            return;
        }
    // Manager currently unused for HTTP-only placeholder
        String channelId = channelUID.getId();
        if (CHANNEL_GARAGEDOOR_CONTROL.equals(channelId)) {
            if (command instanceof OpenClosedType openClosed) {
                logger.debug("Garage door command '{}' accepted (HTTP-only placeholder, not dispatched)", openClosed);
                // Future: invoke manager to send control if supported via cloud
            } else if (command instanceof StringType st) {
                // Accept legacy OPEN/CLOSE string
                String value = st.toFullString().toUpperCase();
                if ("OPEN".equals(value) || "CLOSE".equals(value)) {
                    logger.debug("Garage door string command '{}' accepted (HTTP-only placeholder)", value);
                } else {
                    logger.debug("Unsupported string command {} for channel {}", command, channelId);
                }
            } else if (command instanceof RefreshType) {
                logger.debug("Refresh requested on control channel (ignored)");
            } else {
                logger.debug("Unsupported command type {} for channel {}", command.getClass().getSimpleName(), channelId);
            }
        } else if (CHANNEL_GARAGEDOOR_STATE.equals(channelId)) {
            if (command instanceof RefreshType) {
                logger.debug("Refresh garage door state (not implemented)");
            }
        } else if (CHANNEL_GARAGEDOOR_SIGNAL.equals(channelId)) {
            if (command instanceof RefreshType) {
                // Placeholder: set UNDEF or maybe a fixed dummy value; we choose to leave untouched for now
                logger.debug("Refresh signal strength (not available in HTTP-only mode)");
            }
        }
    /**
     * Bridge callback to update physical door state.
     */
    public void updateDoorState(OpenClosedType state) {
        updateState(new ChannelUID(getThing().getUID(), CHANNEL_GARAGEDOOR_STATE), state);
    }
}
