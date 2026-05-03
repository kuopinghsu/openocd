// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * JTAG to VPI driver
 *
 * Copyright (C) 2013 Franck Jullien, <elec4fun@gmail.com>
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <jtag/interface.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifndef _WIN32
#include <netinet/tcp.h>
#endif

#include "helper/replacements.h"

#define NO_TAP_SHIFT	0
#define TAP_SHIFT	1

#define DEFAULT_SERVER_ADDRESS	"127.0.0.1"
#define DEFAULT_SERVER_PORT	5555

#define	XFERT_MAX_SIZE		512

#define CMD_RESET		0
#define CMD_TMS_SEQ		1
#define CMD_SCAN_CHAIN		2
#define CMD_SCAN_CHAIN_FLIP_TMS	3
#define CMD_STOP_SIMU		4
#define CMD_OSCAN1_RAW		5

/* jtag_vpi server port and address to connect to */
static int server_port = DEFAULT_SERVER_PORT;
static char *server_address;

/* Send CMD_STOP_SIMU to server when OpenOCD exits? */
static bool stop_sim_on_exit;

/* cJTAG mode flag */
static bool jtag_vpi_cjtag_mode = false;

static int sockfd;
static struct sockaddr_in serv_addr;

/* One jtag_vpi "packet" as sent over a TCP channel. */
struct vpi_cmd {
	union {
		uint32_t cmd;
		unsigned char cmd_buf[4];
	};
	unsigned char buffer_out[XFERT_MAX_SIZE];
	unsigned char buffer_in[XFERT_MAX_SIZE];
	union {
		uint32_t length;
		unsigned char length_buf[4];
	};
	union {
		uint32_t nb_bits;
		unsigned char nb_bits_buf[4];
	};
};

static char *jtag_vpi_cmd_to_str(int cmd_num)
{
	switch (cmd_num) {
	case CMD_RESET:
		return "CMD_RESET";
	case CMD_TMS_SEQ:
		return "CMD_TMS_SEQ";
	case CMD_SCAN_CHAIN:
		return "CMD_SCAN_CHAIN";
	case CMD_SCAN_CHAIN_FLIP_TMS:
		return "CMD_SCAN_CHAIN_FLIP_TMS";
	case CMD_STOP_SIMU:
		return "CMD_STOP_SIMU";
	case CMD_OSCAN1_RAW:
		return "CMD_OSCAN1_RAW";
	default:
		return "<unknown>";
	}
}

static int jtag_vpi_send_cmd(struct vpi_cmd *vpi)
{
	int retval;

	/* Optional low-level JTAG debug */
	if (LOG_LEVEL_IS(LOG_LVL_DEBUG_IO)) {
		if (vpi->nb_bits > 0) {
			/* command with a non-empty data payload */
			char *char_buf = buf_to_hex_str(vpi->buffer_out,
					(vpi->nb_bits > DEBUG_JTAG_IOZ)
						? DEBUG_JTAG_IOZ
						: vpi->nb_bits);
			LOG_DEBUG_IO("sending JTAG VPI cmd: cmd=%s, "
					"length=%" PRIu32 ", "
					"nb_bits=%" PRIu32 ", "
					"buf_out=0x%s%s",
					jtag_vpi_cmd_to_str(vpi->cmd),
					vpi->length,
					vpi->nb_bits,
					char_buf,
					(vpi->nb_bits > DEBUG_JTAG_IOZ) ? "(...)" : "");
			free(char_buf);
		} else {
			/* command without data payload */
			LOG_DEBUG_IO("sending JTAG VPI cmd: cmd=%s, "
					"length=%" PRIu32 ", "
					"nb_bits=%" PRIu32,
					jtag_vpi_cmd_to_str(vpi->cmd),
					vpi->length,
					vpi->nb_bits);
		}
	}

	/* Use little endian when transmitting/receiving jtag_vpi cmds.
	   The choice of little endian goes against usual networking conventions
	   but is intentional to remain compatible with most older OpenOCD builds
	   (i.e. builds on little-endian platforms). */
	h_u32_to_le(vpi->cmd_buf, vpi->cmd);
	h_u32_to_le(vpi->length_buf, vpi->length);
	h_u32_to_le(vpi->nb_bits_buf, vpi->nb_bits);

retry_write:
	retval = write_socket(sockfd, vpi, sizeof(struct vpi_cmd));

	if (retval < 0) {
		/* Account for the case when socket write is interrupted. */
#ifdef _WIN32
		int wsa_err = WSAGetLastError();
		if (wsa_err == WSAEINTR)
			goto retry_write;
#else
		if (errno == EINTR)
			goto retry_write;
#endif
		/* Otherwise this is an error using the socket, most likely fatal
		   for the connection. B*/
		log_socket_error("jtag_vpi xmit");
		/* TODO: Clean way how adapter drivers can report fatal errors
		   to upper layers of OpenOCD and let it perform an orderly shutdown? */
		exit(-1);
	} else if (retval < (int)sizeof(struct vpi_cmd)) {
		/* This means we could not send all data, which is most likely fatal
		   for the jtag_vpi connection (the underlying TCP connection likely not
		   usable anymore) */
		LOG_ERROR("jtag_vpi: Could not send all data through jtag_vpi connection.");
		exit(-1);
	}

	/* Otherwise the packet has been sent successfully. */
	return ERROR_OK;
}

static int jtag_vpi_receive_cmd(struct vpi_cmd *vpi)
{
	unsigned int bytes_buffered = 0;
/* Backward compatible: optimize only for cJTAG */
    unsigned int expected_size = sizeof(struct vpi_cmd);

	while (bytes_buffered < expected_size) {
		int bytes_to_receive = expected_size - bytes_buffered;
		int retval = read_socket(sockfd, ((char *)vpi) + bytes_buffered, bytes_to_receive);
		if (retval < 0) {
#ifdef _WIN32
			int wsa_err = WSAGetLastError();
			if (wsa_err == WSAEINTR) {
				/* socket read interrupted by WSACancelBlockingCall() */
				continue;
			}
#else
			if (errno == EINTR) {
				/* socket read interrupted by a signal */
				continue;
			}
#endif
			/* Otherwise, this is an error when accessing the socket. */
			log_socket_error("jtag_vpi recv");
			exit(-1);
		} else if (retval == 0) {
			/* Connection closed by the other side */
			LOG_ERROR("Connection prematurely closed by jtag_vpi server.");
			exit(-1);
		}
		/* Otherwise, we have successfully received some data */
		bytes_buffered += retval;
	}

	/* Use little endian when transmitting/receiving jtag_vpi cmds. */
	vpi->cmd = le_to_h_u32(vpi->cmd_buf);
	vpi->length = le_to_h_u32(vpi->length_buf);
	vpi->nb_bits = le_to_h_u32(vpi->nb_bits_buf);

	return ERROR_OK;
}

/* Forward declarations for cJTAG VPI helper functions defined later in this file */
static int jtag_vpi_send_tckc_tmsc(uint8_t tckc, uint8_t tmsc);
static uint8_t jtag_vpi_receive_tmsc(void);

/* ============================================================
 * IEEE 1149.7 cJTAG OScan1 Protocol
 * ============================================================ */

#define JSCAN_OSCAN_ON		0x01
#define JSCAN_OSCAN_OFF		0x00
#define JSCAN_SELECT		0x02
#define JSCAN_DESELECT		0x03
#define JSCAN_SF_SELECT		0x04
#define JSCAN_RESET		0x0F

#define SF0			0
#define SF1			1
#define SF2			2
#define SF3			3

static struct {
	bool initialized;
	bool oscan_enabled;
	uint8_t scanning_format;
	uint8_t device_id;
} oscan1_state = {
	.initialized = false,
	.oscan_enabled = false,
	.scanning_format = SF0,
	.device_id = 0
};

static int oscan1_send_oac(void)
{
	/* Send OScan1 Activation Packet (12 bits: OAC + EC + CP)
	 * IEEE 1149.7 Activation Packet Structure (LSB first):
	 *   - OAC (Online Activation Code): 4 bits = 1100 (LSB first)
	 *   - EC (Extension Code): 4 bits = 1000 (LSB first)
	 *   - CP (Check Packet): 4 bits, calculated as CP[i] = OAC[i] ^ EC[i]
	 *
	 * Preceded by escape sequence (6-7 TMSC toggles while TCKC high) */
	LOG_DEBUG("Sending escape sequence (6 toggles)...");

	uint8_t tmsc_val = 1;
	if (jtag_vpi_send_tckc_tmsc(1, tmsc_val) != ERROR_OK)
		return ERROR_FAIL;

	for (int i = 0; i < 6; i++) {
		tmsc_val = !tmsc_val;
		if (jtag_vpi_send_tckc_tmsc(1, tmsc_val) != ERROR_OK)
			return ERROR_FAIL;
	}

	if (jtag_vpi_send_tckc_tmsc(0, 1) != ERROR_OK)
		return ERROR_FAIL;

	LOG_DEBUG("Sending 12-bit Activation Packet (OAC + EC + CP)...");

	uint8_t oac[4] = {0, 0, 1, 1};
	uint8_t ec[4]  = {0, 0, 0, 1};
	uint8_t cp[4];
	for (int i = 0; i < 4; i++)
		cp[i] = oac[i] ^ ec[i];

	LOG_DEBUG("  OAC: %d,%d,%d,%d", oac[0], oac[1], oac[2], oac[3]);
	LOG_DEBUG("  EC:  %d,%d,%d,%d", ec[0], ec[1], ec[2], ec[3]);
	LOG_DEBUG("  CP:  %d,%d,%d,%d", cp[0], cp[1], cp[2], cp[3]);

	/* drive each bit on falling edge, then raise TCKC for TAPC to sample */
	for (int i = 0; i < 4; i++) {
		if (jtag_vpi_send_tckc_tmsc(0, oac[i]) != ERROR_OK)
			return ERROR_FAIL;
		if (jtag_vpi_send_tckc_tmsc(1, oac[i]) != ERROR_OK)
			return ERROR_FAIL;
	}

	for (int i = 0; i < 4; i++) {
		if (jtag_vpi_send_tckc_tmsc(0, ec[i]) != ERROR_OK)
			return ERROR_FAIL;
		if (jtag_vpi_send_tckc_tmsc(1, ec[i]) != ERROR_OK)
			return ERROR_FAIL;
	}

	for (int i = 0; i < 4; i++) {
		if (jtag_vpi_send_tckc_tmsc(0, cp[i]) != ERROR_OK)
			return ERROR_FAIL;
		if (jtag_vpi_send_tckc_tmsc(1, cp[i]) != ERROR_OK)
			return ERROR_FAIL;
	}

	return ERROR_OK;
}

static int oscan1_send_jscan_cmd(uint8_t cmd)
{
	uint8_t packet = (1 << 4) | (cmd & 0x0F);
	int bit_count = 5;

	/* drive each bit on falling edge, then raise TCKC for TAPC to sample */
	for (int i = bit_count - 1; i >= 0; i--) {
		uint8_t bit = (packet >> i) & 1;
		if (jtag_vpi_send_tckc_tmsc(0, bit) != ERROR_OK)
			return ERROR_FAIL;
		if (jtag_vpi_send_tckc_tmsc(1, bit) != ERROR_OK)
			return ERROR_FAIL;
	}

	return ERROR_OK;
}

static int oscan1_sf0_encode(uint8_t tms, uint8_t tdi, uint8_t *tdo)
{
	/* IEEE 1149.7 "Falling Edge Change / Rising Edge Sample" rule.
	 * DTS (controller) drives TMSC on the falling edge (TCKC=0), then raises
	 * TCKC so the TAPC samples the stable value on the rising edge.
	 *
	 * OScan1 3-bit packet:
	 *   Bit 0 (nTDI): drive on TCKC falling, sample on TCKC rising
	 *   Bit 1 (TMS):  drive on TCKC falling, sample on TCKC rising
	 *   Bit 2 (TDO):  TCKC rising triggers TCK pulse; read TDO on TCKC falling */
	uint8_t inverted_tdi = !tdi;

	/* Bit 0: drive nTDI on falling edge, raise TCKC for TAPC to sample */
	if (jtag_vpi_send_tckc_tmsc(0, inverted_tdi) != ERROR_OK)
		return ERROR_FAIL;
	if (jtag_vpi_send_tckc_tmsc(1, inverted_tdi) != ERROR_OK)
		return ERROR_FAIL;

	/* Bit 1: drive TMS on falling edge, raise TCKC for TAPC to sample */
	if (jtag_vpi_send_tckc_tmsc(0, tms) != ERROR_OK)
		return ERROR_FAIL;
	if (jtag_vpi_send_tckc_tmsc(1, tms) != ERROR_OK)
		return ERROR_FAIL;

	/* Bit 2 (TDO slot): lower TCKC (RTL schedules TCK rise via tck_rise_req).
         * The VPI server detects the TCK rising edge, waits for tdo_sampled to
         * settle, then returns tmsc_o (= tdo_sampled while bit_pos=2) in the
         * negedge response. Read TDO NOW before the posedge command overwrites
         * last_oscan1_response with bit_pos=0 output (= 0). */
        if (jtag_vpi_send_tckc_tmsc(0, 0) != ERROR_OK)
                return ERROR_FAIL;
        *tdo = jtag_vpi_receive_tmsc();

        /* Raise TCKC to complete the packet (lowers TCK, advances bit_pos to 0) */
        if (jtag_vpi_send_tckc_tmsc(1, 0) != ERROR_OK)
                return ERROR_FAIL;

	return ERROR_OK;
}

static int oscan1_init(void)
{
	if (oscan1_state.initialized)
		return ERROR_OK;

	LOG_INFO("Initializing OScan1 protocol...");

	LOG_DEBUG("Sending OAC (Attention Character)...");
	if (oscan1_send_oac() != ERROR_OK) {
		LOG_ERROR("Failed to send OAC");
		return ERROR_FAIL;
	}

	LOG_DEBUG("Sending JSCAN_OSCAN_ON command...");
	if (oscan1_send_jscan_cmd(JSCAN_OSCAN_ON) != ERROR_OK) {
		LOG_ERROR("Failed to enable OScan1");
		return ERROR_FAIL;
	}
	oscan1_state.oscan_enabled = true;

	LOG_DEBUG("Sending JSCAN_SELECT command...");
	if (oscan1_send_jscan_cmd(JSCAN_SELECT) != ERROR_OK) {
		LOG_ERROR("Failed to select device");
		return ERROR_FAIL;
	}

	LOG_DEBUG("Selecting Scanning Format 0...");
	if (oscan1_send_jscan_cmd(JSCAN_SF_SELECT) != ERROR_OK) {
		LOG_ERROR("Failed to select scanning format");
		return ERROR_FAIL;
	}
	oscan1_state.scanning_format = SF0;

	oscan1_state.initialized = true;
	LOG_INFO("OScan1 protocol initialized successfully");

	return ERROR_OK;
}

static int oscan1_set_scanning_format(uint8_t format)
{
	if (format > SF3) {
		LOG_ERROR("Invalid scanning format: %d", format);
		return ERROR_FAIL;
	}

	oscan1_state.scanning_format = format;
	LOG_DEBUG("Scanning format set to SF%d", format);

	return ERROR_OK;
}

/**
 * jtag_vpi_reset - ask to reset the JTAG device
 * @param trst 1 if TRST is to be asserted
 * @param srst 1 if SRST is to be asserted
 */
static int jtag_vpi_reset(int trst, int srst)
{
	struct vpi_cmd vpi;
	memset(&vpi, 0, sizeof(struct vpi_cmd));

	vpi.cmd = CMD_RESET;
	vpi.length = 0;
	return jtag_vpi_send_cmd(&vpi);
}

/**
 * jtag_vpi_tms_seq - ask a TMS sequence transition to JTAG
 * @param bits TMS bits to be written (bit0, bit1 .. bitN)
 * @param nb_bits number of TMS bits (between 1 and 8)
 *
 * Write a series of TMS transitions, where each transition consists in :
 *  - writing out TCK=0, TMS=\<new_state>, TDI=\<???>
 *  - writing out TCK=1, TMS=\<new_state>, TDI=\<???> which triggers the transition
 * The function ensures that at the end of the sequence, the clock (TCK) is put
 * low.
 */
static int jtag_vpi_tms_seq(const uint8_t *bits, int nb_bits)
{
	struct vpi_cmd vpi;
	int nb_bytes;

	LOG_DEBUG("jtag_vpi_tms_seq: cJTAG mode = %d, nb_bits = %d", jtag_vpi_cjtag_mode, nb_bits);
	/* In cJTAG mode, encode TMS transitions using OScan1 SF0 (TMS on rising edge).
	 * Use TDI=1 as a don't-care to avoid unintended data shifts. */
	if (jtag_vpi_cjtag_mode) {
		LOG_DEBUG("INSIDE cJTAG mode branch, calling oscan1_sf0_encode for %d bits", nb_bits);

		for (int i = 0; i < nb_bits; i++) {
			uint8_t tms = (bits[i / 8] >> (i % 8)) & 0x1;
			uint8_t dummy_tdo = 0;
			int ret = oscan1_sf0_encode(tms, 1, &dummy_tdo);
			if (ret != ERROR_OK)
				return ret;
		}
		return ERROR_OK;
	}

	/* Standard JTAG mode continues below... */
	memset(&vpi, 0, sizeof(struct vpi_cmd));
	nb_bytes = DIV_ROUND_UP(nb_bits, 8);

	vpi.cmd = CMD_TMS_SEQ;
	memcpy(vpi.buffer_out, bits, nb_bytes);
	vpi.length = nb_bytes;
	vpi.nb_bits = nb_bits;

	return jtag_vpi_send_cmd(&vpi);
}

/**
 * jtag_vpi_path_move - ask a TMS sequence transition to JTAG
 * @param cmd path transition
 *
 * Write a series of TMS transitions, where each transition consists in :
 *  - writing out TCK=0, TMS=\<new_state>, TDI=\<???>
 *  - writing out TCK=1, TMS=\<new_state>, TDI=\<???> which triggers the transition
 * The function ensures that at the end of the sequence, the clock (TCK) is put
 * low.
 */

static int jtag_vpi_path_move(struct pathmove_command *cmd)
{
	uint8_t trans[DIV_ROUND_UP(cmd->num_states, 8)];

	memset(trans, 0, DIV_ROUND_UP(cmd->num_states, 8));

	for (unsigned int i = 0; i < cmd->num_states; i++) {
		if (tap_state_transition(tap_get_state(), true) == cmd->path[i])
			buf_set_u32(trans, i, 1, 1);
		tap_set_state(cmd->path[i]);
	}

	return jtag_vpi_tms_seq(trans, cmd->num_states);
}

/**
 * jtag_vpi_tms - ask a tms command
 * @param cmd tms command
 */
static int jtag_vpi_tms(struct tms_command *cmd)
{
	return jtag_vpi_tms_seq(cmd->bits, cmd->num_bits);
}

static int jtag_vpi_state_move(enum tap_state state)
{
	if (tap_get_state() == state)
		return ERROR_OK;

	uint8_t tms_scan = tap_get_tms_path(tap_get_state(), state);
	int tms_len = tap_get_tms_path_len(tap_get_state(), state);

	int retval = jtag_vpi_tms_seq(&tms_scan, tms_len);
	if (retval != ERROR_OK)
		return retval;

	tap_set_state(state);

	return ERROR_OK;
}

static int jtag_vpi_queue_tdi_xfer(uint8_t *bits, int nb_bits, int tap_shift)
{
	LOG_DEBUG("jtag_vpi_queue_tdi_xfer: cJTAG mode = %d, nb_bits = %d, tap_shift = %d", jtag_vpi_cjtag_mode, nb_bits, tap_shift);
	/* In cJTAG mode, translate shifts into OScan1 SF0 cycles (TMS on rising, TDI on falling).
	 * Maintain the existing bit ordering: LSB-first per OpenOCD buffer layout. */
	if (jtag_vpi_cjtag_mode) {
		for (int bit = 0; bit < nb_bits; bit++) {
			uint8_t tms = (tap_shift && (bit == nb_bits - 1)) ? 1 : 0;
			uint8_t tdi = bits ? ((bits[bit / 8] >> (bit % 8)) & 0x1) : 1;
			uint8_t tdo = 0;
			int ret = oscan1_sf0_encode(tms, tdi, &tdo);
			if (ret != ERROR_OK)
				return ret;
			if (bits) {
				if (tdo)
					bits[bit / 8] |= (1 << (bit % 8));
				else
					bits[bit / 8] &= ~(1 << (bit % 8));
			}
		}
		return ERROR_OK;
	}

	/* Standard JTAG mode continues below... */
	struct vpi_cmd vpi;
	int nb_bytes = DIV_ROUND_UP(nb_bits, 8);

	memset(&vpi, 0, sizeof(struct vpi_cmd));

	vpi.cmd = tap_shift ? CMD_SCAN_CHAIN_FLIP_TMS : CMD_SCAN_CHAIN;

	if (bits)
		memcpy(vpi.buffer_out, bits, nb_bytes);
	else
		memset(vpi.buffer_out, 0xff, nb_bytes);

	vpi.length = nb_bytes;
	vpi.nb_bits = nb_bits;

	int retval = jtag_vpi_send_cmd(&vpi);
	if (retval != ERROR_OK)
		return retval;

	retval = jtag_vpi_receive_cmd(&vpi);
	if (retval != ERROR_OK)
		return retval;

	/* Optional low-level JTAG debug */
	if (LOG_LEVEL_IS(LOG_LVL_DEBUG_IO)) {
		char *char_buf = buf_to_hex_str(vpi.buffer_in,
				(nb_bits > DEBUG_JTAG_IOZ) ? DEBUG_JTAG_IOZ : nb_bits);
		LOG_DEBUG_IO("recvd JTAG VPI data: nb_bits=%d, buf_in=0x%s%s",
			nb_bits, char_buf, (nb_bits > DEBUG_JTAG_IOZ) ? "(...)" : "");
		free(char_buf);
	}

	if (bits)
		memcpy(bits, vpi.buffer_in, nb_bytes);

	return ERROR_OK;
}

/**
 * jtag_vpi_queue_tdi - short description
 * @param bits bits to be queued on TDI (or NULL if 0 are to be queued)
 * @param nb_bits number of bits
 * @param tap_shift
 */
static int jtag_vpi_queue_tdi(uint8_t *bits, int nb_bits, int tap_shift)
{
	int nb_xfer = DIV_ROUND_UP(nb_bits, XFERT_MAX_SIZE * 8);
	int retval;

	while (nb_xfer) {
		if (nb_xfer ==  1) {
			retval = jtag_vpi_queue_tdi_xfer(bits, nb_bits, tap_shift);
			if (retval != ERROR_OK)
				return retval;
		} else {
			retval = jtag_vpi_queue_tdi_xfer(bits, XFERT_MAX_SIZE * 8, NO_TAP_SHIFT);
			if (retval != ERROR_OK)
				return retval;
			nb_bits -= XFERT_MAX_SIZE * 8;
			if (bits)
				bits += XFERT_MAX_SIZE;
		}

		nb_xfer--;
	}

	return ERROR_OK;
}

/**
 * jtag_vpi_clock_tms - clock a TMS transition
 * @param tms the TMS to be sent
 *
 * Triggers a TMS transition (ie. one JTAG TAP state move).
 */
static int jtag_vpi_clock_tms(int tms)
{
	const uint8_t tms_0 = 0;
	const uint8_t tms_1 = 1;

	return jtag_vpi_tms_seq(tms ? &tms_1 : &tms_0, 1);
}

/**
 * jtag_vpi_scan - launches a DR-scan or IR-scan
 * @param cmd the command to launch
 *
 * Launch a JTAG IR-scan or DR-scan
 *
 * Returns ERROR_OK if OK, ERROR_xxx if a read/write error occurred.
 */
static int jtag_vpi_scan(struct scan_command *cmd)
{
	int scan_bits;
	uint8_t *buf = NULL;
	int retval = ERROR_OK;

	scan_bits = jtag_build_buffer(cmd, &buf);

	if (cmd->ir_scan) {
		retval = jtag_vpi_state_move(TAP_IRSHIFT);
		if (retval != ERROR_OK)
			return retval;
	} else {
		retval = jtag_vpi_state_move(TAP_DRSHIFT);
		if (retval != ERROR_OK)
			return retval;
	}

	if (cmd->end_state == TAP_DRSHIFT) {
		retval = jtag_vpi_queue_tdi(buf, scan_bits, NO_TAP_SHIFT);
		if (retval != ERROR_OK)
			return retval;
	} else {
		retval = jtag_vpi_queue_tdi(buf, scan_bits, TAP_SHIFT);
		if (retval != ERROR_OK)
			return retval;
	}

	if (cmd->end_state != TAP_DRSHIFT) {
		/*
		 * As our JTAG is in an unstable state (IREXIT1 or DREXIT1), move it
		 * forward to a stable IRPAUSE or DRPAUSE.
		 */
		retval = jtag_vpi_clock_tms(0);
		if (retval != ERROR_OK)
			return retval;

		if (cmd->ir_scan)
			tap_set_state(TAP_IRPAUSE);
		else
			tap_set_state(TAP_DRPAUSE);
	}

	retval = jtag_read_buffer(buf, cmd);
	if (retval != ERROR_OK)
		return retval;

	free(buf);

	if (cmd->end_state != TAP_DRSHIFT) {
		retval = jtag_vpi_state_move(cmd->end_state);
		if (retval != ERROR_OK)
			return retval;
	}

	return ERROR_OK;
}

static int jtag_vpi_runtest(unsigned int num_cycles, enum tap_state state)
{
	int retval;

	retval = jtag_vpi_state_move(TAP_IDLE);
	if (retval != ERROR_OK)
		return retval;

	retval = jtag_vpi_queue_tdi(NULL, num_cycles, NO_TAP_SHIFT);
	if (retval != ERROR_OK)
		return retval;

	return jtag_vpi_state_move(state);
}

static int jtag_vpi_stableclocks(unsigned int num_cycles)
{
	uint8_t tms_bits[4];
	unsigned int cycles_remain = num_cycles;
	int nb_bits;
	int retval;
	const unsigned int cycles_one_batch = sizeof(tms_bits) * 8;

	/* use TMS=1 in TAP RESET state, TMS=0 in all other stable states */
	memset(&tms_bits, (tap_get_state() == TAP_RESET) ? 0xff : 0x00, sizeof(tms_bits));

	/* send the TMS bits */
	while (cycles_remain > 0) {
		nb_bits = (cycles_remain < cycles_one_batch) ? cycles_remain : cycles_one_batch;
		retval = jtag_vpi_tms_seq(tms_bits, nb_bits);
		if (retval != ERROR_OK)
			return retval;
		cycles_remain -= nb_bits;
	}

	return ERROR_OK;
}

static int jtag_vpi_execute_queue(struct jtag_command *cmd_queue)
{
	struct jtag_command *cmd;
	int retval = ERROR_OK;

	for (cmd = cmd_queue; retval == ERROR_OK && cmd;
	     cmd = cmd->next) {
		switch (cmd->type) {
		case JTAG_RESET:
			retval = jtag_vpi_reset(cmd->cmd.reset->trst, cmd->cmd.reset->srst);
			break;
		case JTAG_RUNTEST:
			retval = jtag_vpi_runtest(cmd->cmd.runtest->num_cycles,
						  cmd->cmd.runtest->end_state);
			break;
		case JTAG_STABLECLOCKS:
			retval = jtag_vpi_stableclocks(cmd->cmd.stableclocks->num_cycles);
			break;
		case JTAG_TLR_RESET:
			retval = jtag_vpi_state_move(cmd->cmd.statemove->end_state);
			break;
		case JTAG_PATHMOVE:
			retval = jtag_vpi_path_move(cmd->cmd.pathmove);
			break;
		case JTAG_TMS:
			retval = jtag_vpi_tms(cmd->cmd.tms);
			break;
		case JTAG_SLEEP:
			jtag_sleep(cmd->cmd.sleep->us);
			break;
		case JTAG_SCAN:
			retval = jtag_vpi_scan(cmd->cmd.scan);
			break;
		default:
			LOG_ERROR("BUG: unknown JTAG command type 0x%X",
				  cmd->type);
			retval = ERROR_FAIL;
			break;
		}
	}

	return retval;
}

static int jtag_vpi_init(void)
{
	int flag = 1;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		LOG_ERROR("jtag_vpi: Could not create client socket");
		return ERROR_FAIL;
	}

	memset(&serv_addr, 0, sizeof(serv_addr));

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(server_port);

	if (!server_address)
		server_address = strdup(DEFAULT_SERVER_ADDRESS);

	serv_addr.sin_addr.s_addr = inet_addr(server_address);

	if (serv_addr.sin_addr.s_addr == INADDR_NONE) {
		LOG_ERROR("jtag_vpi: inet_addr error occurred");
		return ERROR_FAIL;
	}

	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		close(sockfd);
		LOG_ERROR("jtag_vpi: Can't connect to %s : %u", server_address, server_port);
		return ERROR_COMMAND_CLOSE_CONNECTION;
	}

	if (serv_addr.sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
		/* This increases performance dramatically for local
		 * connections, which is the most likely arrangement
		 * for a VPI connection. */
		setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
	}

	LOG_INFO("jtag_vpi: Connection to %s : %u successful", server_address, server_port);

	/* Initialize OScan1 protocol if cJTAG mode is enabled */
	if (jtag_vpi_cjtag_mode) {
		LOG_INFO("jtag_vpi: cJTAG mode enabled, initializing OScan1 protocol");
		if (oscan1_init() != ERROR_OK) {
			LOG_ERROR("jtag_vpi: Failed to initialize OScan1 protocol");
			close(sockfd);
			return ERROR_FAIL;
		}
	}

	return ERROR_OK;
}

static int jtag_vpi_stop_simulation(void)
{
	struct vpi_cmd cmd;
	memset(&cmd, 0, sizeof(struct vpi_cmd));
	cmd.length = 0;
	cmd.nb_bits = 0;
	cmd.cmd = CMD_STOP_SIMU;
	return jtag_vpi_send_cmd(&cmd);
}

static int jtag_vpi_quit(void)
{
	if (stop_sim_on_exit) {
		if (jtag_vpi_stop_simulation() != ERROR_OK)
			LOG_WARNING("jtag_vpi: failed to send \"stop simulation\" command");
	}
	if (close_socket(sockfd) != 0) {
		LOG_WARNING("jtag_vpi: could not close jtag_vpi client socket");
		log_socket_error("jtag_vpi");
	}
	free(server_address);
	return ERROR_OK;
}

/* Forward declaration */
COMMAND_HANDLER(jtag_vpi_enable_cjtag_handler);
COMMAND_HANDLER(jtag_vpi_handle_scanning_format_command);

COMMAND_HANDLER(jtag_vpi_set_port)
{
	if (CMD_ARGC == 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	COMMAND_PARSE_NUMBER(int, CMD_ARGV[0], server_port);
	LOG_INFO("jtag_vpi: server port set to %u", server_port);

	return ERROR_OK;
}

COMMAND_HANDLER(jtag_vpi_set_address)
{

	if (CMD_ARGC == 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	free(server_address);
	server_address = strdup(CMD_ARGV[0]);
	LOG_INFO("jtag_vpi: server address set to %s", server_address);

	return ERROR_OK;
}

COMMAND_HANDLER(jtag_vpi_stop_sim_on_exit_handler)
{
	if (CMD_ARGC != 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	COMMAND_PARSE_ON_OFF(CMD_ARGV[0], stop_sim_on_exit);
	return ERROR_OK;
}

static const struct command_registration jtag_vpi_subcommand_handlers[] = {
	{
		.name = "set_port",
		.handler = &jtag_vpi_set_port,
		.mode = COMMAND_CONFIG,
		.help = "set the TCP port number of the jtag_vpi server (default: 5555)",
		.usage = "tcp_port_num",
	},
	{
		.name = "set_address",
		.handler = &jtag_vpi_set_address,
		.mode = COMMAND_CONFIG,
		.help = "set the IP address of the jtag_vpi server (default: 127.0.0.1)",
		.usage = "ipv4_addr",
	},
	{
		.name = "stop_sim_on_exit",
		.handler = &jtag_vpi_stop_sim_on_exit_handler,
		.mode = COMMAND_CONFIG,
		.help = "Configure if simulation stop command shall be sent "
			"before OpenOCD exits (default: off)",
		.usage = "<on|off>",
	},
	{
		.name = "enable_cjtag",
		.handler = &jtag_vpi_enable_cjtag_handler,
		.mode = COMMAND_CONFIG,
		.help = "enable cJTAG/OScan1 two-wire protocol mode",
		.usage = "<on|off>",
	},
	{
		.name = "scanning_format",
		.handler = &jtag_vpi_handle_scanning_format_command,
		.mode = COMMAND_CONFIG,
		.help = "Set cJTAG scanning format",
		.usage = "0|1|2|3",
	},
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration jtag_vpi_command_handlers[] = {
	{
		.name = "jtag_vpi",
		.mode = COMMAND_ANY,
		.help = "perform jtag_vpi management",
		.chain = jtag_vpi_subcommand_handlers,
		.usage = "",
	},
	COMMAND_REGISTRATION_DONE
};

static struct jtag_interface jtag_vpi_interface = {
	.supported = DEBUG_CAP_TMS_SEQ,
	.execute_queue = jtag_vpi_execute_queue,
};

/* Last CMD_OSCAN1 response (TDO bit on TMSC line) */
static uint8_t last_oscan1_response = 0;

/* cJTAG / OScan1 protocol support */
static int jtag_vpi_send_tckc_tmsc(uint8_t tckc, uint8_t tmsc)
{
	struct vpi_cmd vpi;
	int retval;

	memset(&vpi, 0, sizeof(struct vpi_cmd));

	/* Use CMD_OSCAN1_RAW to send raw TCKC/TMSC signals
	 * Format: 1 byte with bit0=TCKC, bit1=TMSC */
	vpi.cmd = CMD_OSCAN1_RAW;
	vpi.length = 1;
	vpi.nb_bits = 2;
	vpi.buffer_out[0] = (tckc & 0x01) | ((tmsc & 0x01) << 1);

	retval = jtag_vpi_send_cmd(&vpi);

	if (retval != ERROR_OK)
		return retval;

	retval = jtag_vpi_receive_cmd(&vpi);

	if (retval == ERROR_OK) {
		/* Store TDO bit from TMSC response */
		last_oscan1_response = vpi.buffer_in[0] & 0x01;
	}

	return retval;
}

static uint8_t jtag_vpi_receive_tmsc(void)
{
	return last_oscan1_response;
}

COMMAND_HANDLER(jtag_vpi_enable_cjtag_handler)
{
	if (CMD_ARGC != 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	LOG_DEBUG("jtag_vpi_enable_cjtag_handler: Parsing argument...");
		COMMAND_PARSE_ON_OFF(CMD_ARGV[0], jtag_vpi_cjtag_mode);
	LOG_DEBUG("jtag_vpi_enable_cjtag_handler: cJTAG mode set to %d", jtag_vpi_cjtag_mode);
	LOG_INFO("cJTAG mode %s", jtag_vpi_cjtag_mode ? "enabled" : "disabled");

	return ERROR_OK;
}

COMMAND_HANDLER(jtag_vpi_handle_scanning_format_command)
{
	if (CMD_ARGC != 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	unsigned int format;
	COMMAND_PARSE_NUMBER(uint, CMD_ARGV[0], format);

	if (format > 3) {
		LOG_ERROR("Invalid scanning format %d (must be 0-3)", format);
		return ERROR_COMMAND_SYNTAX_ERROR;
	}

	oscan1_set_scanning_format(format);
	LOG_INFO("Scanning format set to SF%d", format);

	return ERROR_OK;
}

struct adapter_driver jtag_vpi_adapter_driver = {
	.name = "jtag_vpi",
	.transport_ids = TRANSPORT_JTAG,
	.transport_preferred_id = TRANSPORT_JTAG,
	.commands = jtag_vpi_command_handlers,

	.init = jtag_vpi_init,
	.quit = jtag_vpi_quit,

	.jtag_ops = &jtag_vpi_interface,
};
