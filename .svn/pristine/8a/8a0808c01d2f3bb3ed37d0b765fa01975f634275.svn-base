/* © 2014 Sigma Designs, Inc. This is an unpublished work protected by Sigma
 * Designs, Inc. as a trade secret, and is not to be used or disclosed except as
 * provided Z-Wave Controller Development Kit Limited License Agreement. All
 * rights reserved.
 *
 * Notice: All information contained herein is confidential and/or proprietary to
 * Sigma Designs and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law. Dissemination or
 * reproduction of the source code contained herein is expressly forbidden to
 * anyone except Licensees of Sigma Designs  who have executed a Sigma Designs’
 * Z-WAVE CONTROLLER DEVELOPMENT KIT LIMITED LICENSE AGREEMENT. The copyright
 * notice above is not evidence of any actual or intended publication of the
 * source code. THE RECEIPT OR POSSESSION OF  THIS SOURCE CODE AND/OR RELATED
 * INFORMATION DOES NOT CONVEY OR IMPLY ANY RIGHTS  TO REPRODUCE, DISCLOSE OR
 * DISTRIBUTE ITS CONTENTS, OR TO MANUFACTURE, USE, OR SELL A PRODUCT THAT IT  MAY
 * DESCRIBE.
 *
 * THE SIGMA PROGRAM AND ANY RELATED DOCUMENTATION OR TOOLS IS PROVIDED TO COMPANY
 * "AS IS" AND "WITH ALL FAULTS", WITHOUT WARRANTY OF ANY KIND FROM SIGMA. COMPANY
 * ASSUMES ALL RISKS THAT LICENSED MATERIALS ARE SUITABLE OR ACCURATE FOR
 * COMPANY’S NEEDS AND COMPANY’S USE OF THE SIGMA PROGRAM IS AT COMPANY’S
 * OWN DISCRETION AND RISK. SIGMA DOES NOT GUARANTEE THAT THE USE OF THE SIGMA
 * PROGRAM IN A THIRD PARTY SERVICE ENVIRONMENT OR CLOUD SERVICES ENVIRONMENT WILL
 * BE: (A) PERFORMED ERROR-FREE OR UNINTERRUPTED; (B) THAT SIGMA WILL CORRECT ANY
 * THIRD PARTY SERVICE ENVIRONMENT OR CLOUD SERVICE ENVIRONMENT ERRORS; (C) THE
 * THIRD PARTY SERVICE ENVIRONMENT OR CLOUD SERVICE ENVIRONMENT WILL OPERATE IN
 * COMBINATION WITH COMPANY’S CONTENT OR COMPANY APPLICATIONS THAT UTILIZE THE
 * SIGMA PROGRAM; (D) OR WITH ANY OTHER HARDWARE, SOFTWARE, SYSTEMS, SERVICES OR
 * DATA NOT PROVIDED BY SIGMA. COMPANY ACKNOWLEDGES THAT SIGMA DOES NOT CONTROL
 * THE TRANSFER OF DATA OVER COMMUNICATIONS FACILITIES, INCLUDING THE INTERNET,
 * AND THAT THE SERVICES MAY BE SUBJECT TO LIMITATIONS, DELAYS, AND OTHER PROBLEMS
 * INHERENT IN THE USE OF SUCH COMMUNICATIONS FACILITIES. SIGMA IS NOT RESPONSIBLE
 * FOR ANY DELAYS, DELIVERY FAILURES, OR OTHER DAMAGE RESULTING FROM SUCH ISSUES.
 * SIGMA IS NOT RESPONSIBLE FOR ANY ISSUES RELATED TO THE PERFORMANCE, OPERATION
 * OR SECURITY OF THE THIRD PARTY SERVICE ENVIRONMENT OR CLOUD SERVICES
 * ENVIRONMENT THAT ARISE FROM COMPANY CONTENT, COMPANY APPLICATIONS OR THIRD
 * PARTY CONTENT. SIGMA DOES NOT MAKE ANY REPRESENTATION OR WARRANTY REGARDING THE
 * RELIABILITY, ACCURACY, COMPLETENESS, CORRECTNESS, OR USEFULNESS OF THIRD PARTY
 * CONTENT OR SERVICE OR THE SIGMA PROGRAM, AND DISCLAIMS ALL LIABILITIES ARISING
 * FROM OR RELATED TO THE SIGMA PROGRAM OR THIRD PARTY CONTENT OR SERVICES. TO THE
 * EXTENT NOT PROHIBITED BY LAW, THESE WARRANTIES ARE EXCLUSIVE. SIGMA OFFERS NO
 * WARRANTY OF NON-INFRINGEMENT, TITLE, OR QUIET ENJOYMENT. NEITHER SIGMA NOR ITS
 * SUPPLIERS OR LICENSORS SHALL BE LIABLE FOR ANY INDIRECT, SPECIAL, INCIDENTAL OR
 * CONSEQUENTIAL DAMAGES OR LOSS (INCLUDING DAMAGES FOR LOSS OF BUSINESS, LOSS OF
 * PROFITS, OR THE LIKE), ARISING OUT OF THIS AGREEMENT WHETHER BASED ON BREACH OF
 * CONTRACT, INTELLECTUAL PROPERTY INFRINGEMENT, TORT (INCLUDING NEGLIGENCE),
 * STRICT LIABILITY, PRODUCT LIABILITY OR OTHERWISE, EVEN IF SIGMA OR ITS
 * REPRESENTATIVES HAVE BEEN ADVISED OF OR OTHERWISE SHOULD KNOW ABOUT THE
 * POSSIBILITY OF SUCH DAMAGES. THERE ARE NO OTHER EXPRESS OR IMPLIED WARRANTIES
 * OR CONDITIONS INCLUDING FOR SOFTWARE, HARDWARE, SYSTEMS, NETWORKS OR
 * ENVIRONMENTS OR FOR MERCHANTABILITY, NONINFRINGEMENT, SATISFACTORY QUALITY AND
 * FITNESS FOR A PARTICULAR PURPOSE.
 *
 * The Sigma Program  is not fault-tolerant and is not designed, manufactured or
 * intended for use or resale as on-line control equipment in hazardous
 * environments requiring fail-safe performance, such as in the operation of
 * nuclear facilities, aircraft navigation or communication systems, air traffic
 * control, direct life support machines, or weapons systems, in which the failure
 * of the Sigma Program, or Company Applications created using the Sigma Program,
 * could lead directly to death, personal injury, or severe physical or
 * environmental damage ("High Risk Activities").  Sigma and its suppliers
 * specifically disclaim any express or implied warranty of fitness for High Risk
 * Activities.Without limiting Sigma’s obligation of confidentiality as further
 * described in the Z-Wave Controller Development Kit Limited License Agreement,
 * Sigma has no obligation to establish and maintain a data privacy and
 * information security program with regard to Company’s use of any Third Party
 * Service Environment or Cloud Service Environment. For the avoidance of doubt,
 * Sigma shall not be responsible for physical, technical, security,
 * administrative, and/or organizational safeguards that are designed to ensure
 * the security and confidentiality of the Company Content or Company Application
 * in any Third Party Service Environment or Cloud Service Environment that
 * Company chooses to utilize.
 */

#ifndef DTLS_SERVER_H_
#define DTLS_SERVER_H_

#include "contiki.h"
#include "contiki-net.h"

/**
 * \ingroup processes
 * \defgroup DTLSService DTLS Service
 *
 * Z/IP LAN security provides a secure connection for clients, and other Z/IP Gateways,
 * connecting to the Z/IP Gateway. The Z/IP LAN Security framework provides a means
 * of securing the communication paths between:
 *
 *   - Z/IP Clients
 *   - Z/IP Clients and Z/IP Gateways
 *   - Z/IP Gateways.
 *
 * Starting with Z/IP Gateway 2.x it is mandatory to send secure Z/IP UDP frames to and
 * from the gateway. The same mechanism may be used to send secure Z/IP UDP frames between
 * Z/IP Clients, and between Z/IP Gateways.
 *
 * Secure Z/IP UDP frames are ordinary Z/IP frames wrapped in a DTLS 1.0 wrapper. DTLS is
 * the datagram version of TLS. Z/IP LAN Security default UDP port number is 41230.
 *
 * This current version of Z/IP LAN Security only supports the Pre-Shared-Key
 * (PSK) Key Exchange Algorithm.
 * @{
 */

#define DTLS_PORT 41230
PROCESS_NAME(dtls_server_process);

/**
 * Send encrypted data to a client. If a session exists this will send
 * data synchronously. Otherwise it will create a client session and send async.
 * @param conn udp connection
 * @param data pointer to data
 * @param len length of data
 * @param create_new create new client connection if needed
 * @return the length of the transmitted data
 */

int dtls_send(struct uip_udp_conn* conn, const void* data, u16_t len,u8_t create_new);

/**
 * Return true if the session between the two parties present in the UDP buf
 * has been established.
 */
int session_done_for_uipbuf();

/* Indicator to see if the last SSL read has failed */
extern int dtls_ssl_read_failed;

enum {DTLS_SERVER_INPUT_EVENT,
  DTLS_CONNECTION_CLOSE_EVENT,
  DLTS_CONNECTION_INIT_DONE_EVENT,
  DLTS_SESSION_UPDATE_EVENT,
};

void dtls_exited();

/**
 * @}
 */
#endif /* DTLS_SERVER_H_ */
