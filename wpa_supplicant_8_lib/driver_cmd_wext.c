/*
 * Driver interaction with extended Linux Wireless Extensions for the
 *  Atheros AR600x kernel drivers.
 *
 * Copyright (c) 2012 Eduardo José Tagle <ejtagle@tutopia.com> 
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 */

#include "includes.h"
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <net/if.h>

#include "wireless_copy.h"
#include "common.h"
#include "driver.h"
#include "eloop.h"
#include "priv_netlink.h"
#include "driver_wext.h"
#include "ieee802_11_defs.h"
#include "wpa_common.h"
#include "wpa_ctrl.h"
#include "wpa_supplicant_i.h"
#include "config.h"
#include "linux_ioctl.h"
#include "scan.h"

#include "driver_cmd_wext.h"

typedef enum {
	POWER_MODE_AUTO,
	POWER_MODE_ACTIVE
} POWER_MODE;

static int wpa_driver_atheros_pwr_mode(struct wpa_driver_wext_data *drv, int mode)
{
	struct iwreq iwr;
	os_memset(&iwr, 0, sizeof(iwr));
	os_strncpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
	if (mode == POWER_MODE_AUTO)
		iwr.u.power.disabled = 0;
	else if (mode == POWER_MODE_ACTIVE)
		iwr.u.power.disabled = 1;
	else
		return -1;
	if (ioctl(drv->ioctl_sock, SIOCSIWPOWER, &iwr) < 0) {
		wpa_printf(MSG_DEBUG, "drv_wext: failed to control power\n");
	}
	return 0;
}
#define AR6000_IOCTL_WMI_SET_CHANNELPARAMS   (SIOCIWFIRSTPRIV+16)
#define AR6000_IOCTL_WMI_GET_TARGET_STATS    (SIOCIWFIRSTPRIV+25) 
#define AR6000_IOCTL_EXTENDED                (SIOCIWFIRSTPRIV+31)
#define AR6000_XIOCTRL_WMI_SET_WLAN_STATE                       35

typedef enum {
    WLAN_DISABLED,
    WLAN_ENABLED
} AR6000_WLAN_STATE;

static int wpa_driver_atheros_wlan_ctrl(struct wpa_driver_wext_data *drv, int enable)
{
	struct ifreq ifr;
	char buf[16];

	os_memset(&ifr, 0, sizeof(ifr));
	os_memset(buf, 0, sizeof(buf));

	os_strncpy(ifr.ifr_name, drv->ifname, IFNAMSIZ);
	((int *)buf)[0] = AR6000_XIOCTRL_WMI_SET_WLAN_STATE;
	ifr.ifr_data = buf;

	if (enable)
		((int *)buf)[1] = WLAN_ENABLED;
	else
		((int *)buf)[1] = WLAN_DISABLED;

	if (ioctl(drv->ioctl_sock, AR6000_IOCTL_EXTENDED, &ifr) < 0) {
		return -1;
	}
	return 0;
}

static uint16_t wmic_ieee2freq(int chan)
{
	/* channel 14? */
	if (chan == 14) {
		return 2484;
	}
    if (chan < 14) {    /* 0-13 */
        return (2407 + (chan * 5));
    }
    return (5000 + (chan*5));
}

typedef struct {
	 uint8_t	reserved1;
	 uint8_t	scanParam;              /* set if enable scan */
	 uint8_t	phyMode;                /* see WMI_PHY_MODE */
	 uint8_t	numChannels;            /* how many channels follow */
	 uint16_t	channelList[1];         /* channels in Mhz */
} STRUCT_PACKED WMI_CHANNEL_PARAMS_CMD;

typedef enum {
    WMI_DEFAULT_MODE = 0x0,
    WMI_11A_MODE  = 0x1,
    WMI_11G_MODE  = 0x2,
    WMI_11AG_MODE = 0x3,
    WMI_11B_MODE  = 0x4,
    WMI_11GONLY_MODE = 0x5,
    WMI_11GHT20_MODE = 0x6,
} WMI_PHY_MODE;

static int wpa_driver_atheros_cfg_chan(struct wpa_driver_wext_data *drv, int num)
{
	struct ifreq ifr;
	char buf[256];
	WMI_CHANNEL_PARAMS_CMD *chParamCmd = (WMI_CHANNEL_PARAMS_CMD *)buf;
	int i;
	uint16_t *clist;

	os_memset(&ifr, 0, sizeof(ifr));
	os_strncpy(ifr.ifr_name, drv->ifname, IFNAMSIZ);
	chParamCmd->phyMode = WMI_11G_MODE;
	clist = chParamCmd->channelList;
	chParamCmd->numChannels = num;
	chParamCmd->scanParam = 1;

	for (i = 0; i < num; i++)
		clist[i] = wmic_ieee2freq(i + 1);

	ifr.ifr_data = (void *)chParamCmd;

	if (ioctl(drv->ioctl_sock, AR6000_IOCTL_WMI_SET_CHANNELPARAMS, &ifr) < 0) {
		return -1;
	}
	return 0;
} 

/**
 * wpa_driver_wext_set_scan_timeout - Set scan timeout to report scan completion
 * @priv:  Pointer to private wext data from wpa_driver_wext_init()
 *
 * This function can be used to set registered timeout when starting a scan to
 * generate a scan completed event if the driver does not report this.
 */
static void wpa_driver_wext_set_scan_timeout(void *priv)
{
	struct wpa_driver_wext_data *drv = priv;
	int timeout = 10; /* In case scan A and B bands it can be long */

	/* Not all drivers generate "scan completed" wireless event, so try to
	 * read results after a timeout. */
	if (drv->scan_complete_events) {
	/*
	 * The driver seems to deliver SIOCGIWSCAN events to notify
	 * when scan is complete, so use longer timeout to avoid race
	 * conditions with scanning and following association request.
	 */
		timeout = 30;
	}
	wpa_printf(MSG_DEBUG, "Scan requested - scan timeout %d seconds",
		   timeout);
	eloop_cancel_timeout(wpa_driver_wext_scan_timeout, drv, drv->ctx);
	eloop_register_timeout(timeout, 0, wpa_driver_wext_scan_timeout, drv,
			       drv->ctx);
}


/**
 * wpa_driver_wext_combo_scan - Request the driver to initiate combo scan
 * @priv: Pointer to private wext data from wpa_driver_wext_init()
 * @params: Scan parameters
 * Returns: 0 on success, -1 on failure
 */
int wpa_driver_wext_combo_scan(void *priv, struct wpa_driver_scan_params *params)
{
	struct wpa_driver_wext_data *drv = priv;
	struct iwreq iwr;
	int ret = 0;
	struct iw_scan_req req;
	const u8 *ssid = params->ssids[0].ssid;
	size_t ssid_len = params->ssids[0].ssid_len;


	if (ssid_len > IW_ESSID_MAX_SIZE) {
		wpa_printf(MSG_DEBUG, "%s: too long SSID (%lu)",
			   __FUNCTION__, (unsigned long) ssid_len);
		return -1;
	}
	
	if (!drv->driver_is_started) {
		wpa_printf(MSG_DEBUG, "%s: Driver stopped", __func__);
		return 0;
	}

	wpa_printf(MSG_DEBUG, "%s: Start", __func__);


	os_memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);

	if (ssid && ssid_len) {
		os_memset(&req, 0, sizeof(req));
		req.essid_len = ssid_len;
		req.bssid.sa_family = ARPHRD_ETHER;
		os_memset(req.bssid.sa_data, 0xff, ETH_ALEN);
		os_memcpy(req.essid, ssid, ssid_len);
		iwr.u.data.pointer = (caddr_t) &req;
		iwr.u.data.length = sizeof(req);
		iwr.u.data.flags = IW_SCAN_THIS_ESSID;
	}

	if (ioctl(drv->ioctl_sock, SIOCSIWSCAN, &iwr) < 0) {
		wpa_printf(MSG_ERROR, "ioctl[SIOCSIWSCAN]");
		return -1;
	} 
	return ret;
}
 
static char *wpa_driver_get_country_code(int channels)
{
	char *country = "US"; /* WEXT_NUMBER_SCAN_CHANNELS_FCC */

	if (channels == WEXT_NUMBER_SCAN_CHANNELS_ETSI)
		country = "EU";
	else if( channels == WEXT_NUMBER_SCAN_CHANNELS_MKK1)
		country = "JP";
	return country;
} 

static int wpa_driver_ar6000_get_ifflags_ifname(struct wpa_driver_wext_data *drv,
					      const char *ifname, int *flags)
{
	struct ifreq ifr;

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(drv->ioctl_sock, SIOCGIFFLAGS, (caddr_t) &ifr) < 0) {
		perror("ioctl[SIOCGIFFLAGS]");
		return -1;
	}
	*flags = ifr.ifr_flags & 0xffff;
	return 0;
}


/**
 * wpa_driver_ar6000_get_ifflags - Get interface flags (SIOCGIFFLAGS)
 * @drv: driver_wext private data
 * @flags: Pointer to returned flags value
 * Returns: 0 on success, -1 on failure
 */
static int wpa_driver_ar6000_get_ifflags(struct wpa_driver_wext_data *drv, int *flags)
{
	return wpa_driver_ar6000_get_ifflags_ifname(drv, drv->ifname, flags);
}


static int wpa_driver_ar6000_set_ifflags_ifname(struct wpa_driver_wext_data *drv,
					      const char *ifname, int flags)
{
	struct ifreq ifr;

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_flags = flags & 0xffff;
	if (ioctl(drv->ioctl_sock, SIOCSIFFLAGS, (caddr_t) &ifr) < 0) {
		perror("SIOCSIFFLAGS");
		return -1;
	}
	return 0;
}


/**
 * wpa_driver_ar6000_set_ifflags - Set interface flags (SIOCSIFFLAGS)
 * @drv: driver_wext private data
 * @flags: New value for flags
 * Returns: 0 on success, -1 on failure
 */
static int wpa_driver_ar6000_set_ifflags(struct wpa_driver_wext_data *drv, int flags)
{
	return wpa_driver_ar6000_set_ifflags_ifname(drv, drv->ifname, flags);
} 

/**
 * get_max_scan_ssids - get the maximum number of SSIDS the adapter
 *  can scan at the same time. AR6002 only supports one, AR6003 supports
 *  up to 9, but this driver does not support it
 */
int wpa_driver_get_max_scan_ssids(void)
{
	return 1;
}


/**
 * driver_cmd - execute driver-specific command
 * @priv: private driver interface data from init()
 * @cmd: command to execute
 * @buf: return buffer
 * @buf_len: buffer length
 *
 * Returns: 0 for "OK" reply, >0 for reply_len on success,
 * -1 on failure
 *
 */
int wpa_driver_wext_driver_cmd(void *priv, char *cmd, char *buf, size_t buf_len)
{
	struct wpa_driver_wext_data *drv = priv;
	struct wpa_supplicant *wpa_s = (struct wpa_supplicant *)(drv->ctx);
	int ret = 0;

	wpa_printf(MSG_DEBUG, "%s %s len = %d", __func__, cmd, buf_len);

	if (!drv->driver_is_started && (os_strcasecmp(cmd, "START") != 0)) {
		wpa_printf(MSG_ERROR,"WEXT: Driver not initialized yet");
		return -1;
	}

	if (drv->host_asleep) {
		return 0; /* just return due to system suspend */
	}

	if (os_strcmp(cmd, "RSSI")==0 || os_strcasecmp(cmd, "RSSI-APPROX") == 0) {
	
		int rssi = 255;
		struct iwreq iwr;
		struct iw_statistics stats;
		os_memset(&iwr, 0, sizeof(iwr));
		os_memset(&stats, 0, sizeof(stats));
		os_strncpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
		iwr.u.data.pointer = (caddr_t) &stats;
		iwr.u.data.length = sizeof(struct iw_statistics);
		iwr.u.data.flags = 1;             /* Clear updated flag */
		if ((ret = ioctl(drv->ioctl_sock, SIOCGIWSTATS, &iwr)) >= 0) {
			rssi = stats.qual.qual;
			drv->errors = 0;
		} else {
			wpa_printf(MSG_ERROR, "%s failed (%d): %s", __func__, ret, cmd);
			drv->errors++;
			if (drv->errors > DRV_NUMBER_SEQUENTIAL_ERRORS) {
				drv->errors = 0;
				wpa_msg(drv->ctx, MSG_INFO, WPA_EVENT_DRIVER_STATE "HANGED");
			}	
		}

		if (rssi == 255)
			rssi = -200;
		else
			rssi += (161 - 256);
		return os_snprintf(buf, buf_len, "SSID rssi %d\n", rssi); 
		
	} else if (os_strcmp(cmd, "LINKSPEED")==0) {
	
		struct iwreq iwr;
		os_memset(&iwr, 0, sizeof(iwr));
		os_strncpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);
		if ((ret = ioctl(drv->ioctl_sock, SIOCGIWRATE, &iwr)) == 0) {
			unsigned int speed_kbps = iwr.u.param.value / 1000000;
			drv->errors = 0;
			if ((!iwr.u.param.fixed)) {
				return os_snprintf(buf, buf_len, "LinkSpeed %u\n", speed_kbps);
			}
		} else {
			wpa_printf(MSG_ERROR, "%s failed (%d): %s", __func__, ret, cmd);
			drv->errors++;
			if (drv->errors > DRV_NUMBER_SEQUENTIAL_ERRORS) {
				drv->errors = 0;
				wpa_msg(drv->ctx, MSG_INFO, WPA_EVENT_DRIVER_STATE "HANGED");
			}	
		}

		return -1;
		
	} else if( os_strcasecmp(cmd, "RELOAD") == 0 ) {
	
		wpa_printf(MSG_DEBUG,"Reload command");
		wpa_msg(drv->ctx, MSG_INFO, WPA_EVENT_DRIVER_STATE "HANGED");
		return 0;
		
	} else if( os_strcasecmp(cmd, "BGSCAN-START") == 0 ) {
	
		return 0;
		
	} else if( os_strcasecmp(cmd, "BGSCAN-STOP") == 0 ) {
	
		return 0;

	} else if( os_strncasecmp(cmd, "CSCAN", 5) == 0 ) {
		struct iwreq iwr;
		struct iw_scan_req req;
	
		/* Emulate using a regular scan */
		char* ssid_ptr = os_strstr(cmd, "SSID=");
		
		os_memset(&iwr, 0, sizeof(iwr));
		os_strlcpy(iwr.ifr_name, drv->ifname, IFNAMSIZ);

		if (ssid_ptr) {
			char* end_ptr1 = os_strstr(ssid_ptr, "CH=");
			char* end_ptr2 = os_strchr(ssid_ptr, ',');
			int ssid_len;
			
			ssid_ptr += 5;
			while (*ssid_ptr == ' ')
				ssid_ptr++;
			
			if (!end_ptr1)
				end_ptr1 = ssid_ptr + os_strlen(ssid_ptr);
			if (end_ptr2 != NULL && (uint32_t)end_ptr2 < (uint32_t)end_ptr1)
				end_ptr1 = end_ptr2;
			ssid_len = (uint32_t)end_ptr1 - (uint32_t)ssid_ptr;
			
			os_memset(&req, 0, sizeof(req));
			req.essid_len = ssid_len;
			req.bssid.sa_family = ARPHRD_ETHER;
			os_memset(req.bssid.sa_data, 0xff, ETH_ALEN);
			os_memcpy(req.essid, ssid_ptr, ssid_len);
			iwr.u.data.pointer = (caddr_t) &req;
			iwr.u.data.length = sizeof(req);
			iwr.u.data.flags = IW_SCAN_THIS_ESSID;
		}
		

		if (ioctl(drv->ioctl_sock, SIOCSIWSCAN, &iwr) < 0) {
			wpa_printf(MSG_ERROR, "ioctl[SIOCSIWSCAN]");
			return -1;
		} 
	
		wpa_driver_wext_set_scan_timeout(priv);
		wpa_supplicant_notify_scanning(wpa_s, 1); 
		return 0;
	
	} else if( os_strcasecmp(cmd, "GETPOWER") == 0) {
	
		return os_snprintf(buf, buf_len, "powermode = 1"); // Active
		
	} else if( os_strcasecmp(cmd, "GETBAND") == 0) {

		return os_snprintf(buf, buf_len, "Band 0"); // Auto
		
	} else if (os_strcmp(cmd, "MACADDR")==0) {
	
		// reply comes back in the form "Macaddr = XX.XX.XX.XX.XX.XX" where XX
		struct ifreq ifr;
		os_memset(&ifr, 0, sizeof(ifr));
		os_strncpy(ifr.ifr_name, drv->ifname, IFNAMSIZ);
		if(ioctl(drv->ioctl_sock, SIOCGIFHWADDR, &ifr)==0) {
			char *mac = ifr.ifr_hwaddr.sa_data;
			drv->errors = 0;
			return os_snprintf(buf, buf_len, "Macaddr = %02X.%02X.%02X.%02X.%02X.%02X\n",
						mac[0], mac[1], mac[2],
						mac[3], mac[4], mac[5]);
		} else {
			wpa_printf(MSG_ERROR, "%s failed (%d): %s", __func__, ret, cmd);
			drv->errors++;
			if (drv->errors > DRV_NUMBER_SEQUENTIAL_ERRORS) {
				drv->errors = 0;
				wpa_msg(drv->ctx, MSG_INFO, WPA_EVENT_DRIVER_STATE "HANGED");
			}	
		}

	} else if (os_strcmp(cmd, "SCAN-ACTIVE")==0) {
	
		return 0; /* unsupport function */
		
	} else if (os_strcmp(cmd, "SCAN-PASSIVE")==0) {
	
		return 0; /* unsupport function */
		
	} else if (os_strcmp(cmd, "START")==0) {
	
		if ((ret = wpa_driver_atheros_wlan_ctrl(drv, 1)) == 0) {
			
			drv->driver_is_started = TRUE;
			drv->errors = 0;
			linux_set_iface_flags(drv->ioctl_sock, drv->ifname, 1);
			
			wpa_msg(drv->ctx, MSG_INFO, WPA_EVENT_DRIVER_STATE "STARTED");

		} else {
			wpa_printf(MSG_DEBUG, "Fail to start WLAN");
			drv->errors++;
			if (drv->errors > DRV_NUMBER_SEQUENTIAL_ERRORS) {
				drv->errors = 0;
				wpa_msg(drv->ctx, MSG_INFO, WPA_EVENT_DRIVER_STATE "HANGED");
			}	
		}

		return 0;
		
	} else if (os_strcmp(cmd, "STOP")==0) {
	
		if ((ret = wpa_driver_atheros_wlan_ctrl(drv, 0)) == 0) {
		
			wpa_msg(drv->ctx, MSG_INFO, WPA_EVENT_DRIVER_STATE "STOPPED");
			linux_set_iface_flags(drv->ioctl_sock, drv->ifname, 0);
			drv->errors = 0;
			drv->driver_is_started = FALSE;
			
		} else {
			wpa_printf(MSG_DEBUG, "Fail to stop WLAN");
			drv->errors++;
			if (drv->errors > DRV_NUMBER_SEQUENTIAL_ERRORS) {
				drv->errors = 0;
				wpa_msg(drv->ctx, MSG_INFO, WPA_EVENT_DRIVER_STATE "HANGED");
			}	
		}
		
		return 0;
		
	} else if (os_strncmp(cmd, "POWERMODE ", 10)==0) {

		int mode;
		if (sscanf(cmd, "%*s %d", &mode) == 1) {
			return wpa_driver_atheros_pwr_mode(drv, mode);
		}
		return -1;

	} else if (os_strcmp(cmd, "SCAN-CHANNELS")==0) {
	
		// reply comes back in the form "Scan-Channels = X" where X is the number of channels
		int val = drv->scan_channels;
#if 0
		return os_snprintf(buf, buf_len, "Scan-Channels = %d\n", val);
#else
		return os_snprintf(buf, buf_len, "COUNTRY %s",
			wpa_driver_get_country_code(val));
#endif 
		
	} else if (os_strncmp(cmd, "SCAN-CHANNELS ", 14)==0) {
	
		int chan;
		if (sscanf(cmd, "%*s %d", &chan) != 1)
			return -1;
		if ((chan == 11) || (chan == 13) || (chan == 14)) {
			if ((ret = wpa_driver_atheros_cfg_chan(drv, chan)) == 0) {
				drv->errors = 0;
				drv->scan_channels = chan;
				return 0;
			} else {
				wpa_printf(MSG_ERROR, "%s failed (%d): %s", __func__, ret, cmd);
				drv->errors++;
				if (drv->errors > DRV_NUMBER_SEQUENTIAL_ERRORS) {
					drv->errors = 0;
					wpa_msg(drv->ctx, MSG_INFO, WPA_EVENT_DRIVER_STATE "HANGED");
				}	
			}
		}
		return -1;

	} else if (os_strncmp(cmd, "BTCOEXMODE ", 11)==0) {
		int mode;
		if (sscanf(cmd, "%*s %d", &mode)==1) {
			/* 
			 * Android disable BT-COEX when obtaining dhcp packet except there is headset is connected 
			 * It enable the BT-COEX after dhcp process is finished
			 * We ignore since we have our way to do bt-coex during dhcp obtaining.
			 */
			switch (mode) {			
			case 1: /* Disable*/
				break;
			case 0: /* Enable */
				/* fall through */
			case 2: /* Sense*/
				/* fall through */
			default:
				break;
			}
			return 0; /* ignore it */
		}
	} else if (os_strncmp(cmd, "RXFILTER-ADD ", 13)==0) {
		return 0; /* ignore it */
	} else if (os_strncmp(cmd, "RXFILTER-REMOVE ", 16)==0) {
		return 0; /* ignore it */
	} else if (os_strcmp(cmd, "RXFILTER-START")==0) {
		int flags;
		if (wpa_driver_ar6000_get_ifflags(drv, &flags) == 0) {	
			return wpa_driver_ar6000_set_ifflags(drv, flags & ~IFF_MULTICAST);
		}
	} else if (os_strcmp(cmd, "RXFILTER-STOP")==0) {
		int flags;
		if (wpa_driver_ar6000_get_ifflags(drv, &flags) == 0) {	
			return wpa_driver_ar6000_set_ifflags(drv, flags | IFF_MULTICAST);
		}
	} 

	return -1;
}
 
int wpa_driver_signal_poll(void *priv, struct wpa_signal_info *si)
{
	char buf[MAX_DRV_CMD_SIZE];
	struct wpa_driver_wext_data *drv = priv;
	char *prssi;
	int res;

	os_memset(si, 0, sizeof(*si));
	res = wpa_driver_wext_driver_cmd(priv, "RSSI", buf, sizeof(buf));
	/* Answer: SSID rssi -Val */
	if (res < 0)
		return res;
	prssi = strcasestr(buf, "rssi");
	if (!prssi)
		return -1;
	si->current_signal = atoi(prssi + 4 + 1);

	res = wpa_driver_wext_driver_cmd(priv, "LINKSPEED", buf, sizeof(buf));
	/* Answer: LinkSpeed Val */
	if (res < 0)
		return res;
	si->current_txrate = atoi(buf + 9 + 1) * 1000;

	return 0;
}
