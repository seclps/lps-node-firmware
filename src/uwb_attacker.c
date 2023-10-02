/*
 *    ||          ____  _ __
 * +------+      / __ )(_) /_______________ _____  ___
 * | 0xBC |     / __  / / __/ ___/ ___/ __ `/_  / / _ \
 * +------+    / /_/ / / /_/ /__/ /  / /_/ / / /_/  __/
 *  ||  ||    /_____/_/\__/\___/_/   \__,_/ /___/\___/
 *
 * LPS node firmware.
 *
 * Copyright 2016, Bitcraze AB
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Foobar is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
 */
/* uwb_twr_anchor.c: Uwb two way ranging anchor implementation */

#include "uwb.h"

#include <string.h>
#include <stdio.h>

#include "cfg.h"
#include "led.h"

#include "lpp.h"

#include "libdw1000.h"

#include "dwOps.h"
#include "mac.h"
#include <math.h>

// System configuration
static struct uwbConfig_s config;

#define debug(...) // printf(__VA_ARGS__)

#define LPP_HEADER 0
#define LPP_TYPE 1
#define LPP_PAYLOAD 2
#define ANCHORS_COUNT 8

static uint32_t counter = 0;

static const uint8_t base_address[] = {0,0,0,0,0,0,0xcf,0xbc};

static float A0X;
static float A0Z;
#define LPS_STEP 0.1f
#define TO_MOVE_UNIT 1.0f - LPS_STEP
#define TO_Z_UNIT 2.0f

static float positions[ANCHORS_COUNT][3] = {
    {-2.1229f, -3.6221f, 0.3585f},
    {-2.0413f,  4.0448f, 3.0239f},
    { 2.6391f,  3.4172f, 0.3625f},
    { 2.5790f, -3.4709f, 3.1022f},
    {-1.9666f, -3.6052f, 2.9467f},
    {-2.2823f,  3.4096f, 0.3657f},
    { 2.6057f,  3.9284f, 2.8900f},
    { 2.6056f, -2.9679f, 0.3632f}
};

static void sendLPP(dwDevice_t *dev, uint8_t anchorID) {
    
    static packet_t txPacket;
    dwIdle(dev);
    
    MAC80215_PACKET_INIT(txPacket, MAC802154_TYPE_DATA);
    txPacket.pan = 0xbccf;
    
    
    memcpy(txPacket.sourceAddress, base_address, 8);
    txPacket.sourceAddress[0] = 0xff;
    memcpy(txPacket.destAddress, base_address, 8);
    txPacket.destAddress[0] = anchorID;
    
    txPacket.payload[LPP_HEADER] = SHORT_LPP;
    txPacket.payload[LPP_TYPE] = LPP_SHORT_ANCHOR_POSITION;
    
    
    struct lppShortAnchorPosition_s *pos = (struct lppShortAnchorPosition_s*) &txPacket.payload[LPP_PAYLOAD];
    memcpy(pos->position, positions[anchorID], 3*sizeof(float));
    int payloadLength = 2 + sizeof(struct lppShortAnchorPosition_s);
    
    dwNewTransmit(dev);
    dwSetDefaults(dev);
    dwSetData(dev, (uint8_t*)&txPacket, MAC802154_HEADER_LENGTH+payloadLength);
    dwStartTransmit(dev);

}

static void sendFakeLPPs(dwDevice_t *dev) {
    float dist = fabsf(A0X - positions[0][0]);
    uint8_t c = counter++ % 1000;
    if (dist < TO_MOVE_UNIT) {
        if (c == 0) {
            for (int i = 0; i < ANCHORS_COUNT; i++) {
                positions[i][0] -= 0.1;
                positions[i][1] -= 0.1;
            }
        }
        if (c < ANCHORS_COUNT) {
            sendLPP(dev, c);
            ledBlink(ledRanging, true);
        }
    } else {
        float zDist = fabsf(A0Z - positions[0][2]);
        if (zDist < TO_Z_UNIT) {
            if (c == 0) {
                for (int i = 0; i < ANCHORS_COUNT; i++) {
                    positions[i][2] += 0.1;
                }
            }
            if (c < ANCHORS_COUNT) {
                sendLPP(dev, c);
                ledBlink(ledSync, true);
            }
        }
    }

}


static void attackerAnchorInit(uwbConfig_t * newconfig, dwDevice_t *dev)
{
    // Set the LED for anchor mode
    ledOn(ledMode);
    
    config = *newconfig;
    
    // Initialize the packet in the TX buffer
    
    A0X = positions[0][0];
    A0Z = positions[0][2];

    // onEvent is going to be called with eventTimeout which will start receiving
}

static uint32_t attackerAnchorOnEvent(dwDevice_t *dev, uwbEvent_t event)
{
    sendFakeLPPs(dev);
    return 5; // every 1s
}


uwbAlgorithm_t uwbAttackerAlgorithm = {
    .init = attackerAnchorInit,
    .onEvent = attackerAnchorOnEvent,
};
