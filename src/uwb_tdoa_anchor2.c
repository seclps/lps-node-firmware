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
/* uwb_tdoa2.c: Uwb TDOA anchor, version with anchor-computed distances */

/*
 * This anchor algorithm is using TDMA to divide frames in 8 timeslots. Each
 * anchor is sending a packet in one timeslot, anchor n sends its packet in
 * timeslot n. The slot time is of 2ms.
 *
 * Each packet contains (assuming the packet is sent by anchor n):
 *   - A list of 8 IDs that contains the sequence number of the packets
 *     - At index n: The sequence number of this packet
 *     - At index != n: The sequence number of the last packet received by
 *       anchor 'index'
 *   - A list of 8 timestamps that contains
 *     - At index n: The TX timestamp of the current packet in anchor n time
 *     - At index != n: The RX timestamp of all other packets from previous
 *                      frame in anchor n clock. If the previous packet was
 *                      invalid the timestamp is 0
 *   - A list of 7 distances, the distance from this anchor to the other
 *     anchors in the system expressed in this anchor clock. The distance to
 *     the current anchor is reserved.
 *
 * This is enough info for an observer to calculate the time of departure
 * of any packets in this anchor clock, and so to calculate the difference time
 * of arrivale of the packets at the tag.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "uwb.h"
#include "libdw1000.h"
#include "mac.h"

#include "cfg.h"
#include "lpp.h"

#include <stdlib.h>
#include "md5.h"
#include "hmac_md5.h"
//#include "queue.h"

#define debug(...) printf(__VA_ARGS__)

// Still using modulo 2 calculation for slots
// TODO: If A0 is the TDMA master it could transmit slots parameters and frame
//       start so that we would not be limited to modulo 2 anymore
#define NSLOTS 8
#define TDMA_SLOT_BITS 26 // 26: 2ms timeslot
#define TDMA_NSLOT_BITS 3

#define TDMA_FRAME_BITS (TDMA_SLOT_BITS + TDMA_NSLOT_BITS)
#define TDMA_SLOT_LEN (1ull<<(TDMA_SLOT_BITS+1))
#define TDMA_FRAME_LEN (1ull<<(TDMA_FRAME_BITS+1))

#define TDMA_LAST_FRAME(NOW) ( NOW & ~(TDMA_FRAME_LEN-1) )

// Time length of the preamble
#define PREAMBLE_LENGTH_S ( 128 * 1017.63e-9 )
#define PREAMBLE_LENGTH (uint64_t)( PREAMBLE_LENGTH_S * 499.2e6 * 128 )

// Guard length to account for clock drift and time of flight
#define TDMA_GUARD_LENGTH_S ( 1e-6 )
#define TDMA_GUARD_LENGTH (uint64_t)( TDMA_GUARD_LENGTH_S * 499.2e6 * 128 )

// Timeout for receiving a packet in a timeslot
#define RECEIVE_TIMEOUT 300

// Timeout for receiving a service packet after we TX ours
#define RECEIVE_SERVICE_TIMEOUT 800

#define TS_TX_SIZE 4

uint32_t tesla_counter = 0;
bool tesla_init = false;

// Useful constants
static const uint8_t base_address[] = {0,0,0,0,0,0,0xcf,0xbc};

// FSM states
enum state_e {
  syncTdmaState = 0, // Anchors 1 to 5 starts here and rise up to synchronizedState
  syncTimeState,
  synchronizedState, // Anchor 0 is always here!
};

enum slotState_e {
  slotRxDone,
  slotTxDone,
};

// This context struct contains all the requied global values of the algorithm
static struct ctx_s {
  int anchorId;
  enum state_e state;
  enum slotState_e slotState;

  // Current and next TDMA slot
  int slot;
  int nextSlot;

  // Current packet id and tx timestamps
  uint8_t pid;

  // TDMA start of frame in local clock
  dwTime_t tdmaFrameStart;

  // list of timestamps and ids for last frame.
  uint8_t packetIds[NSLOTS];
  uint32_t rxTimestamps[NSLOTS];
  uint32_t txTimestamps[NSLOTS];

  uint16_t distances[NSLOTS];
} ctx;

// Packet formats
#define PACKET_TYPE_TDOA2 0x22

typedef struct rangePacket_s {
  uint8_t type;
  uint8_t pid[NSLOTS];  // Packet id of the timestamps
  uint8_t timestamps[NSLOTS][TS_TX_SIZE];  // Relevant time for anchors
  uint16_t distances[NSLOTS];
} __attribute__((packed)) rangePacket_t;

#define LPP_HEADER (sizeof(rangePacket_t))
#define LPP_TYPE (sizeof(rangePacket_t)+1)
#define LPP_PAYLOAD (sizeof(rangePacket_t)+2)

/* Adjust time for schedule transfer by DW1000 radio. Set 9 LSB to 0 */
static uint32_t adjustTxRxTime(dwTime_t *time)
{
  uint32_t added = (1<<9) - (time->low32 & ((1<<9)-1));

  time->low32 = (time->low32 & ~((1<<9)-1)) + (1<<9);

  return added;
}

/* Calculate the transmit time for a given timeslot in the current frame */
static dwTime_t transmitTimeForSlot(int slot)
{
  dwTime_t transmitTime = { .full = 0 };

  // Calculate start of the slot
  transmitTime.full = ctx.tdmaFrameStart.full + slot*TDMA_SLOT_LEN;
  // Add guard and preamble time
  transmitTime.full += TDMA_GUARD_LENGTH;
  transmitTime.full += PREAMBLE_LENGTH;

  // DW1000 can only schedule time with 9 LSB at 0, adjust for it
  adjustTxRxTime(&transmitTime);

  return transmitTime;
}

static void handleFailedRx(dwDevice_t *dev)
{

  ctx.rxTimestamps[ctx.slot] = 0;
  ctx.distances[ctx.slot] = 0;

  // Failed TDMA sync, keeps track of the number of fail so that the TDMA
  // watchdog can take decision as of TDMA resynchronisation
  if (ctx.slot == 0) {
    ctx.state = syncTdmaState;
  }
}

static void calculateDistance(int slot, int newId, int remotePid, uint32_t remoteTx, uint32_t remoteRx, uint32_t ts)
{
  // Check that the 2 last packets are consecutive packets and that our last packet is in beteen
  if ((ctx.packetIds[slot] == ((newId-1) & 0x0ff)) && remotePid == ctx.packetIds[ctx.anchorId]) {
    double tround1 = remoteRx - ctx.txTimestamps[ctx.slot];
    double treply1 = ctx.txTimestamps[ctx.anchorId] - ctx.rxTimestamps[ctx.slot];
    double tround2 = ts - ctx.txTimestamps[ctx.anchorId];
    double treply2 = remoteTx - remoteRx;

    uint32_t distance = ((tround2 * tround1)-(treply1 * treply2)) / (2*(treply1 + tround2));
    ctx.distances[slot] = distance & 0xfffful;
  } else {
    ctx.distances[slot] = 0;
  }
}

static void handleRxPacket(dwDevice_t *dev)
{
  static packet_t rxPacket;
  dwTime_t rxTime = { .full = 0 };

  dwGetRawReceiveTimestamp(dev, &rxTime);
  dwCorrectTimestamp(dev, &rxTime);

  int dataLength = dwGetDataLength(dev);
  rxPacket.payload[0] = 0;
  dwGetData(dev, (uint8_t*)&rxPacket, dataLength);

  if (dataLength == 0 || rxPacket.payload[0] != PACKET_TYPE_TDOA2 || rxPacket.sourceAddress[0] != ctx.slot) {
    handleFailedRx(dev);
    return;
  }
  rangePacket_t * rangePacket = (rangePacket_t *)rxPacket.payload;

  uint32_t remoteTx;
  memcpy(&remoteTx, rangePacket->timestamps[ctx.slot], 4);
  uint32_t remoteRx;
  memcpy(&remoteRx, rangePacket->timestamps[ctx.anchorId], 4);

  calculateDistance(ctx.slot, rangePacket->pid[ctx.slot], rangePacket->pid[ctx.anchorId],
                    remoteTx, remoteRx, rxTime.low32);

  ctx.packetIds[ctx.slot] = rangePacket->pid[ctx.slot];
  ctx.rxTimestamps[ctx.slot] = rxTime.low32;
  memcpy(&ctx.txTimestamps[ctx.slot], &rangePacket->timestamps[ctx.slot], 4);

  // Resync TDMA and save useful anchor 0 information
  if (ctx.slot == 0) {
    // Resync local frame start to packet from anchor 0
    dwTime_t pkTxTime = { .full = 0 };
    memcpy(&pkTxTime, rangePacket->timestamps[ctx.slot], TS_TX_SIZE);
    ctx.tdmaFrameStart.full = rxTime.full - (pkTxTime.full - TDMA_LAST_FRAME(pkTxTime.full));

    //TODO: Save relevant data to calculate masterTime
  }
}

static void handleServicePacket(dwDevice_t *dev)
{
  static packet_t servicePacket;

  int dataLength = dwGetDataLength(dev);
  servicePacket.payload[0] = 0;
  dwGetData(dev, (uint8_t*)&servicePacket, dataLength);

  if (servicePacket.payload[0] == SHORT_LPP) {
    lppHandleShortPacket(&servicePacket.payload[1], dataLength - MAC802154_HEADER_LENGTH - 1);
  }
}

/*
#define QUEUE_LENGTH 10
#define ITEM_SIZE sizeof(uint8_t)

static QueueHandle_t queueHandleTESLA;
static StaticQueue_t queueTESLA;
uint8_t buf[ QUEUE_LENGTH * ITEM_SIZE ];
*/

// Setup the radio to receive a packet in the next timeslot
static void setupRx(dwDevice_t *dev)
{
  dwTime_t receiveTime = { .full = 0 };

  // Calculate start of the slot
  receiveTime.full = ctx.tdmaFrameStart.full + ctx.nextSlot*TDMA_SLOT_LEN;

  dwSetReceiveWaitTimeout(dev, RECEIVE_TIMEOUT);
  dwWriteSystemConfigurationRegister(dev);

  dwNewReceive(dev);
  dwSetDefaults(dev);
  dwSetTxRxTime(dev, receiveTime);
  dwStartReceive(dev);
  //queueHandleTESLA = xQueueCreateStatic(QUEUE_LENGTH, ITEM_SIZE, buf, &queueTESLA);

}

static const uint8_t hashebytes[8][16] = {
{0x1f,0x2e,0x2b,0x19,0xf2,0xb9,0xdb,0x68,0x5e,0xf0,0x5b,0x65,0x38,0x5a,0x40,0x62},// Anchor('0',-1,-1,0)
{0xaf,0xc1,0xd3,0xc0,0xf6,0x82,0xb3,0xe6,0x9b,0xe9,0xff,0xfe,0x71,0x39,0xe0,0x68},// Anchor('1',-1,+1,1)
{0xe4,0x8f,0xd3,0xe1,0xc9,0x4b,0xec,0xc9,0x27,0x61,0x82,0x7a,0x68,0x00,0x3c,0xdc},// Anchor('2',+1,+1,0)
{0xa9,0x2c,0x1a,0xef,0x23,0xfb,0x38,0xdf,0xeb,0x27,0x78,0xbc,0xe8,0x0f,0x7b,0xf8},// Anchor('3',+1,-1,1)
{0xcb,0x4d,0x44,0x6a,0x2e,0xbf,0xf9,0x49,0x5e,0x60,0x24,0x7b,0x83,0x5f,0xa1,0xf2},// Anchor('4',-1,-1,1)
{0x06,0xe3,0xf9,0xff,0x1f,0x8d,0xb3,0x29,0x87,0x8c,0x17,0x15,0x29,0xd5,0x94,0x8a},// Anchor('5',-1,+1,0)
{0xc9,0xcc,0xdc,0xfe,0xa6,0x75,0x0d,0xda,0x1c,0x5e,0x82,0x0f,0x4e,0xca,0xcb,0x5e},// Anchor('6',+1,+1,1)
{0x39,0xb5,0xd4,0xeb,0x7f,0xed,0x44,0xdd,0x43,0x70,0x21,0x2c,0xff,0x27,0x43,0x17} // Anchor('7',+1,-1,0)
};
static uint64_t txcounter = 0;
#define TESLA_TOTAL_DURATION 10
md5_byte_t keychain[TESLA_TOTAL_DURATION] = {'\0'}; // 50 lpp/s over 10 minutes of keysize 8
#define MAX(a, b)  (((a) > (b)) ? (a) : (b))

static void setTxData(dwDevice_t *dev)
{
  static packet_t txPacket;
  static bool firstEntry = true;
  static int lppLength = 0;

  // if (!tesla_init) {
  //   return;
  // }
  
  if (firstEntry) {
    MAC80215_PACKET_INIT(txPacket, MAC802154_TYPE_DATA);

    memcpy(txPacket.sourceAddress, base_address, 8);
    txPacket.sourceAddress[0] = ctx.anchorId;
    memcpy(txPacket.destAddress, base_address, 8);
    txPacket.destAddress[0] = 0xff;

    txPacket.payload[0] = PACKET_TYPE_TDOA2;

    firstEntry = false;
  }

  uwbConfig_t *uwbConfig = uwbGetConfig();

  // LPP anchor position is currently sent in all packets
  if (uwbConfig->positionEnabled) {
    txPacket.payload[LPP_HEADER] = SHORT_LPP;
    txPacket.payload[LPP_TYPE] = LPP_SHORT_ANCHOR_POSITION;

    struct lppShortAnchorPosition_s *pos = (struct lppShortAnchorPosition_s*) &txPacket.payload[LPP_PAYLOAD];
    memcpy(pos->position, uwbConfig->position, 3*sizeof(float));
      
      //pos->tesla_counter = tesla_counter;
    txcounter++;
      
    uint32_t interval = MAX((uint32_t)(tesla_counter/1000),1);

      pos->interval = interval;
    static md5_byte_t key[8] = {'0','0','0','0','0','0','0','0'};
    key[0] = keychain[(TESLA_TOTAL_DURATION-2)-(interval%(TESLA_TOTAL_DURATION-1))];
      pos->interval = key[0];

    //if (key[0] == 0x02) {
    // txcounter++;
    //}
    //memcpy(pos->nextConstellationHash, hashebytes[ctx.anchorId], 8);
      
    md5_byte_t digest[16];
    hmac_md5((md5_byte_t *)pos->position, 12+8, key, 8, digest); // msg is 12 bytes, its hash is 8 bytes, key is 3 bytes, write result to mac_digest
      
    memcpy(pos->mac, digest, 8);
    memcpy(pos->disclosedKey, key, 8);

    lppLength = 2 + sizeof(struct lppShortAnchorPosition_s);
  }

  rangePacket_t *rangePacket = (rangePacket_t *)txPacket.payload;

  for (int i=0; i<NSLOTS; i++) {
    rangePacket->pid[i] = ctx.packetIds[i];

    memcpy(rangePacket->timestamps[i], &ctx.rxTimestamps[i], TS_TX_SIZE);
  }
  memcpy(rangePacket->timestamps[ctx.anchorId], &ctx.txTimestamps[ctx.anchorId], TS_TX_SIZE);
  memcpy(rangePacket->distances, ctx.distances, sizeof(ctx.distances));

  dwSetData(dev, (uint8_t*)&txPacket, MAC802154_HEADER_LENGTH + sizeof(rangePacket_t) + lppLength);
}

// Setup the radio to send a packet in the next timeslot
static void setupTx(dwDevice_t *dev)
{
  ctx.packetIds[ctx.anchorId] = ctx.pid++;
  dwTime_t txTime = transmitTimeForSlot(ctx.nextSlot);
  ctx.txTimestamps[ctx.anchorId] = txTime.low32;

  dwSetReceiveWaitTimeout(dev, RECEIVE_SERVICE_TIMEOUT);
  dwWriteSystemConfigurationRegister(dev);

  dwNewTransmit(dev);
  dwSetDefaults(dev);
  setTxData(dev);
  dwSetTxRxTime(dev, txTime);

  dwWaitForResponse(dev, true);
  dwStartTransmit(dev);
}

// Increment the slot variables and, if required, switch tdmaStartFrame to next
// frame state time
static void updateSlot()
{
  ctx.slot = ctx.nextSlot;
  ctx.nextSlot = ctx.nextSlot + 1;
  if (ctx.nextSlot >= NSLOTS) {
    ctx.nextSlot = 0;
  }

  // If the next slot is 0, the next schedule has to be in the next frame!
  if (ctx.nextSlot == 0) {
    ctx.tdmaFrameStart.full += TDMA_FRAME_LEN;
  }
}

static const int period = 10 * 1000; // 10 sec

static int roundToNearestMultiple(int n) {
    // Smaller multiple
    int a = (n / period) * period;
    // Larger multiple
    int b = a + period;
    // Return of closest of two
    return (n - a > b - n) ? b : a;
}

// slotStep is called once per timeslot as long as TDMA is synched and setup
// the next timeslot action
static uint32_t slotStep(dwDevice_t *dev, uwbEvent_t event)
{
  switch (ctx.slotState) {
    case slotRxDone:
      if (event == eventPacketReceived) {
        handleRxPacket(dev);
      } else {
        handleFailedRx(dev);
      }

      // Quickly setup transfer to next slot
      if (ctx.nextSlot == ctx.anchorId) {
        setupTx(dev);
        ctx.slotState = slotTxDone;
        updateSlot();
      } else {
        setupRx(dev);
        ctx.slotState = slotRxDone;
        updateSlot();
      }

      break;
    case slotTxDone:
    // We try to receive an LPP packet after sending our packet.
    // After this is done, we setup the next receive.
      if (event == eventPacketReceived || event == eventReceiveTimeout) {
        if (event == eventPacketReceived) {
          debug("Received service packet!\r\n");
            
          static packet_t servicePacket;
          
          int dataLength = dwGetDataLength(dev);
          servicePacket.payload[0] = 0;
          dwGetData(dev, (uint8_t*)&servicePacket, dataLength);
            
          if (servicePacket.payload[1] == LPP_SHORT_INIT_TESLA) {
              uint32_t val;
              memcpy(&val,&servicePacket.payload[2],sizeof(uint32_t));
              debug("val %lu \r\n", val);
              tesla_counter = val;
              if (tesla_init == false) {
                //tesla_counter = 0;
                tesla_init = true;
              } else {
                 //val ? roundToNearestMultiple(tesla_counter) : 0;
              }
              
              debug("resynced tesla time!");
          }
          //debug("service packet p[1] = %d \r\n", servicePacket.payload[1]);
            
          handleServicePacket(dev);
          // The service packet handling time desynchronized us, lets resynch
          ctx.state = syncTdmaState;
          return 0;
        }
        setupRx(dev);
        ctx.slotState = slotRxDone;
        updateSlot();
      }
      break;
  }

  return MAX_TIMEOUT;
}


static void genMD5(md5_byte_t *input, uint8_t len, md5_byte_t *output) {
    md5_state_t hash_state;
    md5_init(&hash_state);
    md5_append(&hash_state, input, len);
    md5_finish(&hash_state, output);
}

//#define EXPECTED_NUMBEROF_PACKETS_PER_SECOND 1
//#define KEYCHAIN_SIZE EXPECTED_NUMBEROF_PACKETS_PER_SECOND * TESLA_TOTAL_DURATION

//static md5_byte_t keychain[KEYCHAIN_SIZE]; // 50 lpp/s over 10 minutes of keysize 8


// Initialize/reset the agorithm
static void tdoa2Init(uwbConfig_t * config, dwDevice_t *dev)
{
  tesla_init = false;
  ctx.anchorId = config->address[0];
  ctx.state = syncTdmaState;
  ctx.slot = NSLOTS-1;
  ctx.nextSlot = 0;
  memset(ctx.txTimestamps, 0, sizeof(ctx.txTimestamps));
  memset(ctx.rxTimestamps, 0, sizeof(ctx.rxTimestamps));
  
 
  const char ids[8] = {'0','1','2','3','4','5','6','7'};
  const int len = TESLA_TOTAL_DURATION;
  for (int index = 0; index < 8;index++) {
      keychain[0]=ids[ctx.anchorId];
      for (int i = 1; i < len; i++) {
          md5_byte_t output[16];
          genMD5(&keychain[i-1], 1, output);
          keychain[i] = output[0];
      }
  }
    
}

// Called for each DW radio event
static uint32_t tdoa2UwbEvent(dwDevice_t *dev, uwbEvent_t event)
{
  if (ctx.state == synchronizedState) {
    return slotStep(dev, event);
  } else {
    if (ctx.anchorId == 0) {
      dwGetSystemTimestamp(dev, &ctx.tdmaFrameStart);
      ctx.tdmaFrameStart.full = TDMA_LAST_FRAME(ctx.tdmaFrameStart.full) + 2*TDMA_FRAME_LEN;
      ctx.state = synchronizedState;
      setupTx(dev);

      ctx.slotState = slotTxDone;
      updateSlot();
    } else {
      switch (event) {
        case eventPacketReceived: {
            static packet_t rxPacket;
            dwTime_t rxTime = { .full = 0 };
            dwGetReceiveTimestamp(dev, &rxTime);
            int dataLength = dwGetDataLength(dev);
            dwGetData(dev, (uint8_t*)&rxPacket, dataLength);

            if (rxPacket.sourceAddress[0] == 0 && rxPacket.payload[0] == PACKET_TYPE_TDOA2) {
              rangePacket_t * rangePacket = (rangePacket_t *)rxPacket.payload;

              // Resync local frame start to packet from anchor 0
              dwTime_t pkTxTime = { .full = 0 };
              memcpy(&pkTxTime, rangePacket->timestamps[0], TS_TX_SIZE);
              ctx.tdmaFrameStart.full = rxTime.full - (pkTxTime.full - TDMA_LAST_FRAME(pkTxTime.full));

              ctx.tdmaFrameStart.full += TDMA_FRAME_LEN;

              setupTx(dev);
              ctx.slotState = slotRxDone;
              ctx.state = synchronizedState;
              updateSlot();
            } else {
              // Start the receiver waiting for a packet from anchor 0
              dwIdle(dev);
              dwSetReceiveWaitTimeout(dev, RECEIVE_TIMEOUT);
              dwWriteSystemConfigurationRegister(dev);

              dwNewReceive(dev);
              dwSetDefaults(dev);
              dwStartReceive(dev);
            }
          }
          break;
        default:
          // Start the receiver waiting for a packet from anchor 0
          dwIdle(dev);
          dwSetReceiveWaitTimeout(dev, RECEIVE_TIMEOUT);
          dwWriteSystemConfigurationRegister(dev);

          dwNewReceive(dev);
          dwSetDefaults(dev);
          dwStartReceive(dev);
          break;
      }
    }
  }

  return MAX_TIMEOUT;
}

uwbAlgorithm_t uwbTdoa2Algorithm = {
  .init = tdoa2Init,
  .onEvent = tdoa2UwbEvent,
};
