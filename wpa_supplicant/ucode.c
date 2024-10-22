#include "utils/includes.h"
#include "utils/common.h"
#include "utils/ucode.h"
#include "drivers/driver.h"
#include "ap/hostapd.h"
#include "wpa_supplicant_i.h"
#include "wps_supplicant.h"
#include "bss.h"
#include "ucode.h"
#include "driver_i.h"

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

void wpas_ucode_update_state(struct wpa_supplicant *wpa_s)
{
	const char *state;
	uc_value_t *val;

	wpa_printf(MSG_INFO, "%s: radio_bitmap:%d", __func__,wpa_s->ucode.radio_bitmap);

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
	ucv_put(wpa_ucode_call(4));
	ucv_gc(vm);
}

void wpas_ucode_event(struct wpa_supplicant *wpa_s, int event, union wpa_event_data *data)
{
	uc_value_t *val;
	s8 hw_idx;

	if (event != EVENT_CH_SWITCH_STARTED)
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

	if (event == EVENT_CH_SWITCH_STARTED) {
		ucv_object_add(val, "csa_count", ucv_int64_new(data->ch_switch.count));
		ucv_object_add(val, "frequency", ucv_int64_new(data->ch_switch.freq));
		ucv_object_add(val, "sec_chan_offset", ucv_int64_new(data->ch_switch.ch_offset));
		ucv_object_add(val, "center_freq1", ucv_int64_new(data->ch_switch.cf1));
		ucv_object_add(val, "center_freq2", ucv_int64_new(data->ch_switch.cf2));
	}

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
	struct wpa_mlo_signal_info mlo_si = {0};

	if (!wpa_s)
		return NULL;

	ret = ucv_object_new(vm);

	val = ucv_string_new(wpa_supplicant_state_txt(wpa_s->wpa_state));
	ucv_object_add(ret, "state", ucv_get(val));

	hw_idx = ucv_int64_get(radio_id);

	if (wpa_s->wpa_state == WPA_COMPLETED && wpa_s->valid_links) {
		wpa_printf(MSG_INFO, "%s: wpa_s->valid_links=%d and hw_idx %d", __func__, wpa_s->valid_links, hw_idx);
		for_each_link(wpa_s->valid_links, i) {
			freq = wpa_s->links[i].freq;
			wpa_printf(MSG_INFO, "%s: freq: %d for link_id %d", __func__, freq, i);
			if ( hw_idx == wpa_get_hw_idx_by_freq(wpa_s, freq )) {
				ucv_object_add(ret, "frequency", ucv_int64_new(freq));
				sec_chan = wpas_get_sec_chan(wpa_s->links[i].bss);
				ucv_object_add(ret, "sec_chan_offset", ucv_int64_new(sec_chan));
				if (wpa_drv_mlo_signal_poll(wpa_s, &mlo_si) == 0) {
					if (mlo_si.links[i].chanwidth != CHAN_WIDTH_UNKNOWN) {
						ucv_object_add(ret, "chan_width", ucv_int64_new(mlo_si.links[i].chanwidth));
						ucv_object_add(ret, "center_freq1", ucv_int64_new(mlo_si.links[i].center_frq1));
						ucv_object_add(ret, "center_freq2", ucv_int64_new(mlo_si.links[i].center_frq2));
						wpa_printf(MSG_INFO, "%s: status frequency filled %d width %d cf1 %d cf2 %d for radio_id %d", __func__, freq,
						mlo_si.links[i].chanwidth, mlo_si.links[i].center_frq1, mlo_si.links[i].center_frq2, hw_idx);
					}
				} else {
						wpa_printf(MSG_ERROR, "%s: error getting signal poll");
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
	}

#ifdef CONFIG_MESH
	if (wpa_s->ifmsh) {
		struct hostapd_iface *ifmsh = wpa_s->ifmsh;

		ucv_object_add(ret, "sec_chan_offset", ucv_int64_new(ifmsh->conf->secondary_channel));
		ucv_object_add(ret, "frequency", ucv_int64_new(ifmsh->freq));
	}
#endif
out:
	return ret;
}

int wpas_ucode_init(struct wpa_global *gl)
{
	static const uc_function_list_t global_fns[] = {
		{ "printf",	uc_wpa_printf },
		{ "getpid", uc_wpa_getpid },
		{ "add_iface", uc_wpas_add_iface },
		{ "remove_iface", uc_wpas_remove_iface },
		{ "udebug_set", uc_wpa_udebug_set },
	};
	static const uc_function_list_t iface_fns[] = {
		{ "status", uc_wpas_iface_status },
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
