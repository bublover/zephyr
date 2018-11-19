


#ifndef __IEEE80211_H__
#define __IEEE80211_H__


#include <zephyr/types.h>
#include <net/net_if.h>
#include <net/wifi.h>

struct wifi_drv_connect_params {
	char *ssid;
	char ssid_length; /* Max 32 */
	char *psk;
	char psk_length; /* Min 8 - Max 64 */
	unsigned char channel;
	enum wifi_security_type security;
};

struct wifi_drv_start_ap_params {
	char *ssid;
	char ssid_length; /* Max 32 */
	char *psk;
	char psk_length; /* Min 8 - Max 64 */
	unsigned char channel;
	enum wifi_security_type security;
};

struct wifi_drv_scan_params {
#define WIFI_BAND_2_4G	(1)
#define WIFI_BAND_5G	(2)
	unsigned char band;
	unsigned char channel;
};

struct wifi_drv_scan_result {
	char bssid[NET_LINK_ADDR_MAX_LENGTH];
	char ssid[WIFI_SSID_MAX_LEN];
	char ssid_length;
	unsigned char channel;
	char rssi;
	enum wifi_security_type security;
};

typedef void (*scan_result_cb_t)(void *iface, int status,
				 struct wifi_drv_scan_result *entry);
typedef void (*connect_cb_t)(void *iface, int status);
typedef void (*disconnect_cb_t)(void *iface, int status);
typedef void (*new_station_t)(void *iface, int status, char *mac);

struct ieee80211_api {
	/**
	 * The net_if_api must be placed in first position in this
	 * struct so that we are compatible with network interface API.
	 */
	struct net_if_api iface_api;

	int (*open)(struct device *dev);
	int (*close)(struct device *dev);
	int (*scan)(struct device *dev, struct wifi_drv_scan_params *params,
		    scan_result_cb_t cb);
	int (*connect)(struct device *dev,
		       struct wifi_drv_connect_params *params,
		       connect_cb_t conn_cb, disconnect_cb_t disc_cb);
	int (*disconnect)(struct device *dev, disconnect_cb_t cb);
	int (*get_station)(struct device *dev, u8_t *signal);
	int (*notify_ip)(struct device *dev, u8_t *ipaddr, u8_t len);
	int (*start_ap)(struct device *dev,
			struct wifi_drv_start_ap_params *params,
			new_station_t cb);
	int (*stop_ap)(struct device *dev);
	int (*del_station)(struct device *dev, u8_t *mac);
};

struct ieee80211_context {
	enum net_l2_flags ieee80211_l2_flags;
};

#define IEEE80211_L2_CTX_TYPE	struct ieee80211_context

/**
 * @brief Initialize IEEE802.11 L2 stack for a given interface
 *
 * @param iface A valid pointer to a network interface
 */
void ieee80211_init(struct net_if *iface);

/**
 * @brief Fill ethernet header in network packet.
 *
 * @param ctx Ethernet context
 * @param pkt Network packet
 * @param ptype Upper level protocol type (in network byte order)
 * @param src Source ethernet address
 * @param dst Destination ethernet address
 *
 * @return Pointer to ethernet header struct inside net_buf.
 */
struct net_eth_hdr *net_ieee80211_fill_header(struct ieee80211_context *ctx,
					struct net_pkt *pkt,
					u32_t ptype,
					u8_t *src,
					u8_t *dst);

const struct net_eth_addr *net_ieee80211_broadcast_addr(void);

#endif /* __IEEE80211_H__*/
