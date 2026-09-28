#include "utils/includes.h"
#include "utils/common.h"
#include "utils/ucode.h"
#include "drivers/driver.h"
#include "ap/hostapd.h"
#include "wpa_supplicant_i.h"
#include "wps_supplicant.h"
#include "bss.h"
#include "scan.h"
#include "ucode.h"
#include "driver_i.h"
#include "sme.h"
#include "config.h"
#ifdef CONFIG_QCN_EXTN
#include "../qcn_extns/cmn.h"
#endif
#include "eloop.h"

static struct wpa_global *wpa_global;
static uc_resource_type_t *global_type, *iface_type;
static uc_value_t *global, *iface_registry;
static uc_vm_t *vm;

void wpas_ucode_update_radio_id(const char *ifname, int id) {
	struct wpa_supplicant *wpa_s = NULL;

	for (wpa_s = wpa_global->ifaces; wpa_s; wpa_s = wpa_s->next)
		if (!strcmp(wpa_s->ifname, ifname))
			break;

	if (!wpa_s) {
		wpa_printf(MSG_ERROR, "%s: wpa_s data not found", __func__);
		return;
	}

	if (id == -1)
		wpa_s->ucode.radio_bitmap = 0;
	else
		wpa_s->ucode.radio_bitmap |= BIT(id);

	wpa_printf(MSG_INFO, "%s: updated radio_bitmap %d for %s", __func__,
		   wpa_s->ucode.radio_bitmap, wpa_s->ifname);
}

static uc_value_t *
wpas_ucode_iface_get_uval(struct wpa_supplicant *wpa_s)
{
	uc_value_t *val;

	if (wpa_s->ucode.idx)
		return wpa_ucode_registry_get(iface_registry, wpa_s->ucode.idx);

	val = uc_resource_new(iface_type, wpa_s);
	wpa_s->ucode.idx = wpa_ucode_registry_add(iface_registry, val);

	return val;
}

static bool
is_ml_interface_already_created(const char *ifname) {
	struct wpa_supplicant *wpa_s;
	for (wpa_s = wpa_global->ifaces; wpa_s; wpa_s = wpa_s->next)
		if (!strcmp(wpa_s->ifname, ifname))
			return true;
	return false;
}

static void
wpas_ucode_update_interfaces(void)
{
	uc_value_t *ifs = ucv_object_new(vm);
	struct wpa_supplicant *wpa_s;

	for (wpa_s = wpa_global->ifaces; wpa_s; wpa_s = wpa_s->next)
		ucv_object_add(ifs, wpa_s->ifname, ucv_get(wpas_ucode_iface_get_uval(wpa_s)));

	ucv_object_add(ucv_prototype_get(global), "interfaces", ucv_get(ifs));
	ucv_gc(vm);
}

void wpas_ucode_add_bss(struct wpa_supplicant *wpa_s)
{
	if (wpa_ucode_call_prepare("iface_add"))
		return;

	uc_value_push(ucv_get(ucv_string_new(wpa_s->ifname)));
	uc_value_push(ucv_get(wpas_ucode_iface_get_uval(wpa_s)));
	ucv_put(wpa_ucode_call(2));
	ucv_gc(vm);
}

void wpas_ucode_free_bss(struct wpa_supplicant *wpa_s)
{
	uc_value_t *val;

	val = wpa_ucode_registry_remove(iface_registry, wpa_s->ucode.idx);
	if (!val)
		return;

	wpa_s->ucode.idx = 0;
	if (wpa_ucode_call_prepare("iface_remove"))
		return;

	uc_value_push(ucv_get(ucv_string_new(wpa_s->ifname)));
	uc_value_push(ucv_get(val));
	ucv_put(wpa_ucode_call(2));
	ucv_gc(vm);
}

#ifdef CONFIG_QCN_EXTN
/**
 * wpas_ucode_update_pre_connect_state - Notify ucode about WPA_PRE_CONNECT
 * @wpa_s: Pointer to wpa_supplicant interface
 *
 * Send per-link (MLD) or legacy channel parameters and DFS information to
 * the ucode runtime when entering WPA_PRE_CONNECT state in Independent
 * Repeater mode. This allows ucode scripts to coordinate channel
 * selection and pre-connection behavior across links.
 */
void wpas_ucode_update_pre_connect_state(struct wpa_supplicant *wpa_s)
{
	const char *state;
	uc_value_t *val;
	uc_value_t *info;
	struct wpa_bss *bss = NULL;
	u8 i;
	u8 op_class, channel;
	int center_freq1 = 0, center_freq2 = 0;
	int offset_mhz = 0;
	int sec_chan_offset;
	s8 hw_idx;
	bool is_dfs = false;

	val = wpa_ucode_registry_get(iface_registry, wpa_s->ucode.idx);
	if (!val)
		return;

	if (wpa_s->cache_cwork && wpa_s->cache_cwork->bss) {
		bss = wpa_s->cache_cwork->bss;
		if (!is_zero_ether_addr(bss->mld_addr)) {
			for_each_link(bss->valid_links, i) {
				if (wpa_ucode_call_prepare("pre_connect_state"))
					return;
				if (bss->mld_links[i].freq == 0)
					continue;
				state = wpa_supplicant_state_txt(wpa_s->wpa_state);
				uc_value_push(ucv_get(ucv_string_new(wpa_s->ifname)));
				hw_idx = wpa_get_hw_idx_by_freq(wpa_s, bss->mld_links[i].freq);
				if (hw_idx == -1)
					hw_idx = 0;
				uc_value_push(ucv_get(ucv_int64_new(hw_idx)));
				uc_value_push(ucv_get(val));
				uc_value_push(ucv_get(ucv_string_new(state)));
				info = ucv_object_new(vm);
				uc_value_push(ucv_get(info));
				ucv_object_add(info, "frequency",
					       ucv_int64_new(bss->mld_links[i].freq));
				ucv_object_add(info, "chan_width",
					       ucv_int64_new(bss->mld_links[i].width));

				/* Reset per-link before computing center freqs */
				center_freq1 = 0;
				center_freq2 = 0;
				ieee80211_freq_to_channel_ext(bss->mld_links[i].freq,
							      0, 1, &op_class, &channel);

				if (bss->mld_links[i].freq >= 2412 && bss->mld_links[i].freq <= 2472) {
					if (bss->mld_links[i].width == CHAN_WIDTH_40) {
						offset_mhz = (channel <= 7) ? 10 : -10;
						center_freq1 = bss->mld_links[i].freq + offset_mhz;
					} else {
						center_freq1 = bss->mld_links[i].freq;
					}
				} else if (bss->mld_links[i].width == CHAN_WIDTH_160 ||
					   bss->mld_links[i].width == CHAN_WIDTH_320) {
					center_freq1 = ieee80211_chan_to_freq(NULL, op_class,
									      bss->mld_links[i].center_freq2_idx);
				} else {
					center_freq1 = ieee80211_chan_to_freq(NULL, op_class,
									      bss->mld_links[i].center_freq1_idx);
					center_freq2 = ieee80211_chan_to_freq(NULL, op_class,
									      bss->mld_links[i].center_freq2_idx);
				}
				ucv_object_add(info, "center_freq1",
					       ucv_int64_new(center_freq1));
				ucv_object_add(info, "center_freq2",
					       ucv_int64_new(center_freq2));
				ucv_object_add(info, "punct_bitmap",
				ucv_int64_new(bss->mld_links[i].punc_bitmap));
				is_dfs = ieee80211_is_dfs(bss->mld_links[i].freq, NULL, 0);
				ucv_object_add(info, "is_dfs", ucv_boolean_new(is_dfs));
				sec_chan_offset = compute_sec_channel_offset_extn(bss->mld_links[i].freq,
										  center_freq1,
										  bss->mld_links[i].width);
				ucv_object_add(info, "sec_chan_offset",
					       ucv_int64_new(sec_chan_offset));
				wpa_printf(MSG_INFO, "%s: MLO i = %d state = %s"
					   "ifname = %s freq = %d center_freq1 = %d center_freq2 = %d"
					   "width = %d is_dfs = %d punc_bitmap = %d, sec_chan_offset = %d",
					   __func__, i, state, wpa_s->ifname, bss->mld_links[i].freq,
					   center_freq1, center_freq2, bss->mld_links[i].width, is_dfs,
					   bss->mld_links[i].punc_bitmap, sec_chan_offset);
				wpa_s->pre_connect_cnt++;
				ucv_put(wpa_ucode_call(5));
				ucv_gc(vm);
			}
		} else {
			if (wpa_ucode_call_prepare("pre_connect_state"))
				return;
			state = wpa_supplicant_state_txt(wpa_s->wpa_state);
			uc_value_push(ucv_get(ucv_string_new(wpa_s->ifname)));
			hw_idx = wpa_get_hw_idx_by_freq(wpa_s, bss->freq);
			if (hw_idx == -1)
				hw_idx = 0;
			uc_value_push(ucv_get(ucv_int64_new(hw_idx)));
			uc_value_push(ucv_get(val));
			uc_value_push(ucv_get(ucv_string_new(state)));
			info = ucv_object_new(vm);
			uc_value_push(ucv_get(info));
			ucv_object_add(info, "frequency",
				       ucv_int64_new(bss->freq));
			ucv_object_add(info, "chan_width",
				       ucv_int64_new(bss->max_cw));
			ieee80211_freq_to_channel_ext(bss->freq, 0, 1, &op_class, &channel);

			if (bss->freq >= 2412 && bss->freq <= 2472) {
				if (bss->max_cw == CHAN_WIDTH_40) {
					offset_mhz = (channel <= 7) ? 10 : -10;
					center_freq1 = bss->freq + offset_mhz;
				} else {
					center_freq1 = bss->freq;
				}
			} else if (bss->max_cw == CHAN_WIDTH_160 ||
				   bss->max_cw == CHAN_WIDTH_320) {
				center_freq1 = ieee80211_chan_to_freq(NULL, op_class,
								      bss->center_freq2_idx);
			} else {
				center_freq1 = ieee80211_chan_to_freq(NULL, op_class,
								      bss->center_freq1_idx);
				center_freq2 = ieee80211_chan_to_freq(NULL, op_class,
								      bss->center_freq2_idx);
			}
			ucv_object_add(info, "center_freq1",
				       ucv_int64_new(center_freq1));
			ucv_object_add(info, "center_freq2",
				       ucv_int64_new(center_freq2));
			ucv_object_add(info, "punct_bitmap",
				       ucv_int64_new(bss->punc_bitmap));
			is_dfs = ieee80211_is_dfs(bss->freq, NULL, 0);
			ucv_object_add(info, "is_dfs",
				       ucv_boolean_new(is_dfs));
			sec_chan_offset = compute_sec_channel_offset_extn(bss->freq,
									  center_freq1,
									  bss->max_cw);
			ucv_object_add(info, "sec_chan_offset",
				       ucv_int64_new(sec_chan_offset));
			wpa_printf(MSG_INFO, "%s: Non-MLO state = %s ifname = %s"
				   "freq = %d center_freq1 = %d center_freq2 = %d width = %d"
				   "is_dfs = %d punc_bitmap = %d, sec_chan_offset = %d",
				   __func__, state, wpa_s->ifname, bss->freq, center_freq1,
				   center_freq2, bss->max_cw, is_dfs, bss->punc_bitmap, sec_chan_offset);
			wpa_s->pre_connect_cnt++;
			ucv_put(wpa_ucode_call(5));
			ucv_gc(vm);
		}
	}
	return;
}
#endif

void wpas_ucode_update_state(struct wpa_supplicant *wpa_s)
{
	const char *state;
	uc_value_t *val;

	wpa_printf(MSG_INFO, "%s: radio_bitmap:%d", __func__,wpa_s->ucode.radio_bitmap);

#ifdef CONFIG_QCN_EXTN
	if (wpa_s && (wpa_s->wpa_state == WPA_PRE_CONNECT)) {
		wpas_ucode_update_pre_connect_state(wpa_s);
		return;
	}
#endif

	val = wpa_ucode_registry_get(iface_registry, wpa_s->ucode.idx);
	if (!val)
		return;

	if (wpa_ucode_call_prepare("state"))
		return;

	state = wpa_supplicant_state_txt(wpa_s->wpa_state);
	uc_value_push(ucv_get(ucv_string_new(wpa_s->ifname)));
	uc_value_push(ucv_get(ucv_int64_new(wpa_s->ucode.radio_bitmap)));
	uc_value_push(ucv_get(val));
	uc_value_push(ucv_get(ucv_string_new(state)));
#ifdef CONFIG_QCN_EXTN
	uc_value_push(ucv_get(ucv_int64_new(wpa_s->conf->ind_rptr)));
	ucv_put(wpa_ucode_call(5));
#else
	ucv_put(wpa_ucode_call(4));
#endif
	ucv_gc(vm);
}

void wpas_ucode_event(struct wpa_supplicant *wpa_s, int event, union wpa_event_data *data)
{
	uc_value_t *val;
	s8 hw_idx;
#ifdef CONFIG_QCN_EXTN
	bool is_dfs = false;
	const char *wpa_state = NULL;
#endif

	if (!((event == EVENT_CH_SWITCH_STARTED) || (event == EVENT_LINK_CH_SWITCH_STARTED)))
		return;

	val = wpa_ucode_registry_get(iface_registry, wpa_s->ucode.idx);
	if (!val)
		return;

	if (wpa_ucode_call_prepare("event"))
		return;

	uc_value_push(ucv_get(ucv_string_new(wpa_s->ifname)));

	hw_idx = wpa_get_hw_idx_by_freq(wpa_s, data->ch_switch.freq);
	if (hw_idx == -1)
		hw_idx = 0;

	wpa_printf(MSG_INFO, "%s: Channel switch event with radio id %d \n", __func__,hw_idx);
	uc_value_push(ucv_get(ucv_int64_new(hw_idx)));

	uc_value_push(ucv_get(val));
	uc_value_push(ucv_get(ucv_string_new(event_to_string(event))));
	val = ucv_object_new(vm);
	uc_value_push(ucv_get(val));
#ifdef CONFIG_QCN_EXTN
	is_dfs = ieee80211_is_dfs(data->ch_switch.freq, NULL, 0);
	wpa_state = wpa_supplicant_state_txt(wpa_s->wpa_state);
#endif

	if ((event == EVENT_CH_SWITCH_STARTED) || (event == EVENT_LINK_CH_SWITCH_STARTED)) {
		ucv_object_add(val, "csa_count", ucv_int64_new(data->ch_switch.count));
		ucv_object_add(val, "frequency", ucv_int64_new(data->ch_switch.freq));
		ucv_object_add(val, "chan_width", ucv_int64_new(data->ch_switch.ch_width));
		ucv_object_add(val, "sec_chan_offset", ucv_int64_new(data->ch_switch.ch_offset));
		ucv_object_add(val, "center_freq1", ucv_int64_new(data->ch_switch.cf1));
		ucv_object_add(val, "center_freq2", ucv_int64_new(data->ch_switch.cf2));
		ucv_object_add(val, "link_id", ucv_int64_new(data->ch_switch.link_id));
		ucv_object_add(val, "punct_bitmap", ucv_int64_new(data->ch_switch.punct_bitmap));
#ifdef CONFIG_QCN_EXTN
		ucv_object_add(val, "is_dfs", ucv_boolean_new(is_dfs));
		ucv_object_add(val, "wpa_state", ucv_string_new(wpa_state));
#endif
	}

#ifdef CONFIG_QCN_EXTN
	wpa_printf(MSG_INFO, "%s: freq = %d is_dfs = %d wpa_state = %s", __func__,
		data->ch_switch.freq, is_dfs, wpa_state);
#endif
	ucv_put(wpa_ucode_call(5));
	ucv_gc(vm);
}

static uc_value_t *
uc_wpas_add_iface(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *info = uc_fn_arg(0);
	uc_value_t *driver = ucv_object_get(info, "driver", NULL);
	uc_value_t *ifname = ucv_object_get(info, "iface", NULL);
	uc_value_t *bridge = ucv_object_get(info, "bridge", NULL);
	uc_value_t *config = ucv_object_get(info, "config", NULL);
	uc_value_t *ctrl = ucv_object_get(info, "ctrl", NULL);
	uc_value_t *mld    = ucv_object_get(info, "mld", NULL);
	uc_value_t *radio_id = uc_fn_arg(1);
	struct wpa_interface iface;
	int id;
	int ret = -1;
	const char *mld_name;

	if (ucv_type(info) != UC_OBJECT)
		goto out;

	if (ucv_type(radio_id) != UC_INTEGER) {
		wpa_printf(MSG_ERROR, "%s: failed to fetch radio_id", __func__);
		goto out;
	}

        id = ucv_int64_get(radio_id);

	iface = (struct wpa_interface){
		.driver = "nl80211",
		.ifname = ucv_string_get(ifname),
		.bridge_ifname = ucv_string_get(bridge),
		.confname = ucv_string_get(config),
		.ctrl_interface = ucv_string_get(ctrl),
	};

	if (driver) {
		const char *drvname;
		if (ucv_type(driver) != UC_STRING)
			goto out;

		iface.driver = NULL;
		drvname = ucv_string_get(driver);
		for (int i = 0; wpa_drivers[i]; i++) {
			if (!strcmp(drvname, wpa_drivers[i]->name))
				iface.driver = wpa_drivers[i]->name;
		}

		if (!iface.driver)
			goto out;
	}

	if (!iface.ifname || !iface.confname)
		goto out;

	if (mld) {
		mld_name = ucv_string_get(mld);
		wpa_printf(MSG_INFO, "%s: mld is %s", __func__, mld_name);
		if (is_ml_interface_already_created(iface.ifname)) {
			wpa_printf(MSG_INFO, "going to update interface");
			ret = 0;
			goto update;
		}
	}

	ret = wpa_supplicant_add_iface(wpa_global, &iface, 0) ? 0 : -1;
	wpas_ucode_update_interfaces();

update:
	wpas_ucode_update_radio_id(iface.ifname, id);

out:
	return ucv_int64_new(ret);
}

static uc_value_t *
uc_wpas_remove_iface(uc_vm_t *vm, size_t nargs)
{
	struct wpa_supplicant *wpa_s = NULL;
	uc_value_t *ifname_arg = uc_fn_arg(0);
	const char *ifname = ucv_string_get(ifname_arg);
	int ret = -1;

	if (!ifname)
		goto out;

	for (wpa_s = wpa_global->ifaces; wpa_s; wpa_s = wpa_s->next)
		if (!strcmp(wpa_s->ifname, ifname))
			break;

	if (!wpa_s)
		goto out;

	ret = wpa_supplicant_remove_iface(wpa_global, wpa_s, 0);
	wpas_ucode_update_interfaces();

out:
	return ucv_int64_new(ret);
}

static int wpas_get_sec_chan(struct wpa_bss *bss)
{
	int sec_chan = 0;
	const u8 *ie;

	ie = wpa_bss_get_ie(bss, WLAN_EID_HT_OPERATION);
	if (ie && ie[1] >= 2) {
		const struct ieee80211_ht_operation *ht_oper;
		int sec;

		ht_oper = (const void *) (ie + 2);
		sec = ht_oper->ht_param & HT_INFO_HT_PARAM_SECONDARY_CHNL_OFF_MASK;
		if (sec == HT_INFO_HT_PARAM_SECONDARY_CHNL_ABOVE)
			sec_chan = 1;
		else if (sec == HT_INFO_HT_PARAM_SECONDARY_CHNL_BELOW)
			sec_chan = -1;
	}
	return sec_chan;
}

static uc_value_t *
uc_wpas_iface_status(uc_vm_t *vm, size_t nargs)
{
	struct wpa_supplicant *wpa_s = uc_fn_thisval("wpas.iface");
	struct wpa_bss *bss;
	uc_value_t *ret, *val;
	uc_value_t *radio_id = uc_fn_arg(0);
	s8 hw_idx;
	int freq, sec_chan, i;
#ifdef CONFIG_QCN_EXTN
	bool is_dfs = false;
#endif
	struct wpa_signal_info si = {0};
	struct wpa_mlo_signal_info mlo_si = {0};

	if (!wpa_s)
		return NULL;

	ret = ucv_object_new(vm);

	val = ucv_string_new(wpa_supplicant_state_txt(wpa_s->wpa_state));
	ucv_object_add(ret, "state", ucv_get(val));

	hw_idx = ucv_int64_get(radio_id);

	if (wpa_s->wpa_state == WPA_COMPLETED && wpa_s->valid_links) {
		for_each_link(wpa_s->valid_links, i) {
			freq = wpa_s->links[i].freq;
			if (hw_idx == wpa_get_hw_idx_by_freq(wpa_s, freq)) {
				ucv_object_add(ret, "frequency", ucv_int64_new(freq));
				sec_chan = wpas_get_sec_chan(wpa_s->links[i].bss);
				ucv_object_add(ret, "sec_chan_offset", ucv_int64_new(sec_chan));
				if (wpa_drv_mlo_signal_poll(wpa_s, &mlo_si) == 0) {
					if (mlo_si.links[i].chanwidth != CHAN_WIDTH_UNKNOWN) {
						ucv_object_add(ret, "chan_width", ucv_int64_new(mlo_si.links[i].chanwidth));
						ucv_object_add(ret, "center_freq1", ucv_int64_new(mlo_si.links[i].center_frq1));
						ucv_object_add(ret, "center_freq2", ucv_int64_new(mlo_si.links[i].center_frq2));
						ucv_object_add(ret, "punct_bitmap", ucv_int64_new(mlo_si.links[i].punct_bitmap));
#ifdef CONFIG_QCN_EXTN
						is_dfs = compute_dfs_for_chanwidth_extn(freq,
											mlo_si.links[i].chanwidth);
						ucv_object_add(ret, "is_dfs", ucv_boolean_new(is_dfs));
#endif
					}
				}
			}
		}
		goto out;
	}

	bss = wpa_s->current_bss;
	if (bss) {
		if (wpa_s->num_multi_hws &&
		    hw_idx != wpa_get_hw_idx_by_freq(wpa_s, bss->freq)) {
			wpa_printf(MSG_ERROR, "%s hw_idx=%hhd is not compatible with freq=%d \n",
				   __func__, hw_idx, bss->freq);
			goto out;
		}
		sec_chan = wpas_get_sec_chan(bss);
		ucv_object_add(ret, "sec_chan_offset", ucv_int64_new(sec_chan));
		ucv_object_add(ret, "frequency", ucv_int64_new(bss->freq));
		if (wpa_s->wpa_state == WPA_COMPLETED &&
		    wpa_drv_signal_poll(wpa_s, &si) == 0) {
			if (si.chanwidth != CHAN_WIDTH_UNKNOWN) {
				ucv_object_add(ret, "chan_width",
					       ucv_int64_new(si.chanwidth));
				ucv_object_add(ret, "center_freq1",
					       ucv_int64_new(si.center_frq1));
				ucv_object_add(ret, "center_freq2",
					       ucv_int64_new(si.center_frq2));
				ucv_object_add(ret, "punct_bitmap", ucv_int64_new(si.punct_bitmap));
#ifdef CONFIG_QCN_EXTN
				is_dfs = compute_dfs_for_chanwidth_extn(bss->freq,
									si.chanwidth);
				ucv_object_add(ret, "is_dfs", ucv_boolean_new(is_dfs));
#endif
			}
		}
	}

#ifdef CONFIG_MESH
	if (wpa_s->ifmsh) {
		struct hostapd_iface *ifmsh = wpa_s->ifmsh;

		ucv_object_add(ret, "sec_chan_offset", ucv_int64_new(ifmsh->conf->secondary_channel));
		ucv_object_add(ret, "frequency", ucv_int64_new(ifmsh->freq));
		if (wpa_s->wpa_state == WPA_COMPLETED &&
		    wpa_drv_signal_poll(wpa_s, &si) == 0) {
			if (si.chanwidth != CHAN_WIDTH_UNKNOWN) {
				ucv_object_add(ret, "chan_width",
					       ucv_int64_new(si.chanwidth));
				ucv_object_add(ret, "center_freq1",
					       ucv_int64_new(si.center_frq1));
				ucv_object_add(ret, "center_freq2",
					       ucv_int64_new(si.center_frq2));
				ucv_object_add(ret, "punct_bitmap",
					       ucv_int64_new(si.punct_bitmap));
			}
		}
	}
#endif
out:
	return ret;
}

#ifdef CONFIG_QCN_EXTN
/**
 * uc_wpas_recvd_ch_sw_comp_ev - Handle ucode channel switch completion event
 * @vm: ucode VM context invoking the callback
 * @nargs: Number of ucode arguments passed to the function
 *
 * Called from ucode when hostapd/wpa_supplicant reports channel switch
 * completion. The function locates interfaces waiting in WPA_PRE_CONNECT
 * state with cached connect work and schedules SME authentication radio
 * work on the matching frequency.
 *
 * Return: New ucode integer value (currently a placeholder return code).
 */
static uc_value_t *
uc_wpas_recvd_ch_sw_comp_ev(uc_vm_t *vm, size_t nargs)
{
	struct wpa_supplicant *wpa_s = NULL;
	uc_value_t *freq_arg = NULL;
	int freq = 0;
	int ret = -1;

	/* Validate global context */
	if (!wpa_global || !wpa_global->ifaces) {
		wpa_printf(MSG_ERROR, "Recv chan sw compl: wpa_global or ifaces is NULL");
		return ucv_int64_new(ret);
	}

	/* Validate arguments */
	if (nargs < 1) {
		wpa_printf(MSG_ERROR, "Recv chan sw compl: missing frequency argument");
		return ucv_int64_new(ret);
	}

	freq_arg = uc_fn_arg(0);
	if (!freq_arg) {
		wpa_printf(MSG_ERROR, "Recv chan sw compl: NULL frequency argument");
		return ucv_int64_new(ret);
	}
	freq = ucv_int64_get(freq_arg);
	wpa_printf(MSG_INFO, "Recv chan sw compl: freq=%d", freq);

	for (wpa_s = wpa_global->ifaces; wpa_s; wpa_s = wpa_s->next) {
		if (!wpa_s)
			continue;
		if (wpa_s->wpa_state != WPA_PRE_CONNECT)
			continue;
		if (!wpa_s->cache_cwork)
                       continue;
		if (!wpa_s->cache_cwork->bss)
		       continue;

		wpa_printf(MSG_INFO,
			   "Recv chan sw compl: ifname=%s state=%d bss_freq=%d target_freq=%d",
			   wpa_s->ifname, wpa_s->wpa_state,
			   wpa_s->cache_cwork->bss->freq, freq);

		if (wpa_s->pre_connect_cnt > 0) {
			wpa_s->pre_connect_cnt--;

			wpa_printf(MSG_INFO,
				   "Recv chan sw compl: ifname=%s pre_connect_cnt now=%d",
				   wpa_s->ifname, wpa_s->pre_connect_cnt);

			if (wpa_s->pre_connect_cnt == 0) {
				wpa_printf(MSG_INFO,
					   "Recv chan sw compl: Scheduling auth for ifname=%s",
					   wpa_s->ifname);
				sme_schedule_auth_radio_work(wpa_s, wpa_s->cache_cwork);
				ret = 0;
			}
		}
		break; /* Only handle one iface per event */
	}

	return ucv_int64_new(ret);
}

/**
 * uc_wpas_start_scan_post_acs - API to start STA scan post repeater AP ACS
 * @vm: ucode VM context invoking the callback
 * @nargs: Number of ucode arguments passed to the function
 *
 * Called from ucode when hostapd send ACS completion event post ACS in its
 * configured links. The function locates interfaces whose acs_complete flag
 * is not set and schedules it to start scanning post setting its acs_complete
 * flag to 1.
 *
 * Return: New ucode integer value (currently a placeholder return code).
 */
static uc_value_t *
uc_wpas_start_scan_post_acs(uc_vm_t *vm, size_t nargs)
{
	struct wpa_supplicant *wpa_s;

	wpa_printf(MSG_INFO, "%s: Resuming STA scan for all interfaces",
		   __func__);

	/* Validate global context */
	if (!wpa_global || !wpa_global->ifaces) {
		wpa_printf(MSG_ERROR, "%s: wpa_global or ifaces is NULL",
			   __func__);
		return ucv_int64_new(-1);
	}

	for (wpa_s = wpa_global->ifaces; wpa_s; wpa_s = wpa_s->next) {
		if (wpa_s->conf && wpa_s->conf->ind_rptr &&
		    (wpa_s->acs_complete == 0)) {
			wpa_s->acs_complete = 1;
			wpa_printf(MSG_DEBUG, "%s: Setting acs_complete=1 for %s and resuming scan",
				   __func__, wpa_s->ifname);
			eloop_cancel_timeout(wpa_supplicant_start_sta_scan, wpa_s, NULL);
			wpa_supplicant_req_scan(wpa_s, 0, 0);
		}
	}

	return ucv_int64_new(0);
}
#endif

int wpas_ucode_init(struct wpa_global *gl)
{
	static const uc_function_list_t global_fns[] = {
		{ "printf",	uc_wpa_printf },
		{ "getpid", uc_wpa_getpid },
		{ "add_iface", uc_wpas_add_iface },
		{ "remove_iface", uc_wpas_remove_iface },
		{ "udebug_set", uc_wpa_udebug_set },
#ifdef CONFIG_QCN_EXTN
		{ "recvd_ch_sw_comp_ev", uc_wpas_recvd_ch_sw_comp_ev },
		{ "start_scan_post_acs", uc_wpas_start_scan_post_acs },
#endif
	};
	static const uc_function_list_t iface_fns[] = {
		{ "status", uc_wpas_iface_status },
#ifdef CONFIG_QCN_EXTN
		{ "notify_uplink_csa", uc_wpas_notify_uplink_csa_extn },
		{ "reconnect", uc_wpas_iface_reconnect_extn },
#endif
	};

	wpa_global = gl;
	vm = wpa_ucode_create_vm();

	global_type = uc_type_declare(vm, "wpas.global", global_fns, NULL);
	iface_type = uc_type_declare(vm, "wpas.iface", iface_fns, NULL);

	iface_registry = ucv_array_new(vm);
	uc_vm_registry_set(vm, "wpas.iface_registry", iface_registry);

	global = wpa_ucode_global_init("wpas", global_type);

	if (wpa_ucode_run(HOSTAPD_UC_PATH "wpa_supplicant.uc"))
		goto free_vm;

	ucv_gc(vm);
	return 0;

free_vm:
	wpa_ucode_free_vm();
	return -1;
}

void wpas_ucode_free(void)
{
	if (wpa_ucode_call_prepare("shutdown") == 0)
		ucv_put(wpa_ucode_call(0));
	wpa_ucode_free_vm();
}
