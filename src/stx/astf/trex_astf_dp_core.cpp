/*
 Itay Marom
 Hanoch Haim
 Cisco Systems, Inc.
*/

/*
Copyright (c) 2015-2015 Cisco Systems, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "astf/astf_db.h"
#include "bp_sim.h"
#include "stt_cp.h"
#include "utl_sync_barrier.h"
#include "trex_messaging.h"

#include "trex_astf.h"
#include "trex_astf_dp_core.h"
#include "trex_astf_topo.h"
#include "trex_client_config.h"


using namespace std;

TrexAstfDpCore::TrexAstfDpCore(uint8_t thread_id, CFlowGenListPerThread *core) :
                TrexDpCore(thread_id, core, STATE_IDLE) {
    CSyncBarrier *sync_barrier = get_astf_object()->get_barrier();
    m_flow_gen = m_core;
    m_flow_gen->set_sync_barrier(sync_barrier);
    m_flow_gen->Create_tcp_ctx();
}

TrexAstfDpCore::~TrexAstfDpCore() {
    m_flow_gen->Delete_tcp_ctx();
}

bool TrexAstfDpCore::are_all_ports_idle() {
    return m_state == STATE_IDLE;
}

bool TrexAstfDpCore::is_port_active(uint8_t port_id) {
    return m_state != STATE_IDLE;
}

void TrexAstfDpCore::get_scheduler_options(bool& disable_client, dsec_t& d_time_flow, double& d_phase) {
    CParserOption *go = &CGlobalInfo::m_options;

    /* do we need to disable this tread client port */
    if ( go->m_astf_mode == CParserOption::OP_ASTF_MODE_SERVR_ONLY ) {
        disable_client = true;
    } else {
        uint8_t p1;
        uint8_t p2;
        m_flow_gen->get_port_ids(p1, p2);
        if ( go->m_astf_mode == CParserOption::OP_ASTF_MODE_CLIENT_MASK && ((go->m_astf_client_mask & (0x1<<p1))==0) ) {
            disable_client=true;
        } else if ( go->m_dummy_port_map[p1] ) { // dummy port
            disable_client=true;
        }
    }

    d_time_flow = m_flow_gen->m_c_tcp->m_fif_d_time; /* set by Create_tcp function */

    d_phase = 0.01 + (double)m_flow_gen->m_thread_id * d_time_flow / (double)m_flow_gen->m_max_threads;

    if ( CGlobalInfo::is_realtime() ) {
        if (d_phase > 0.2 ) {
            d_phase =  0.01 + m_flow_gen->m_thread_id * 0.01;
        }
    }
}

/* jsmoon-TODO: start parameters(profile_id,duration) needed */
#define STARTUP_ID    0

void TrexAstfDpCore::start_scheduler() {

    dsec_t d_time_flow;
    bool disable_client = false;
    double d_phase;

    m_flow_gen->switch_tcp_ctx(STARTUP_ID);
    get_scheduler_options(disable_client, d_time_flow, d_phase);

    CParserOption *go = &CGlobalInfo::m_options;

    double old_offset = 0.0;
    CGenNode *node;

    /* sync all core to the same time */
    if ( sync_barrier() ) {
        dsec_t now = now_sec();
        dsec_t c_stop_sec = -1;
        /* jsmoon-TODO: duration should be set per profile */
        if ( m_flow_gen->m_yaml_info.m_duration_sec > 0 ) {
            c_stop_sec = now + d_phase + m_flow_gen->m_yaml_info.m_duration_sec;
        }

        m_flow_gen->m_cur_time_sec = now;

        if ( !disable_client ) {
            node = m_flow_gen->create_node();
            node->m_type = CGenNode::TCP_TX_FIF;
            node->m_time = now + d_phase + 0.1; /* phase the transmit a bit */
            m_flow_gen->m_node_gen.add_node(node);
        }

        node = m_flow_gen->create_node() ;
        node->m_type = CGenNode::TCP_RX_FLUSH;
        node->m_time = now;
        m_flow_gen->m_node_gen.add_node(node);

        node = m_flow_gen->create_node();
        node->m_type = CGenNode::TCP_TW;
        node->m_time = now;
        m_flow_gen->m_node_gen.add_node(node);

        node = m_flow_gen->create_node();
        node->m_type = CGenNode::FLOW_SYNC;
        node->m_time = now;
        m_flow_gen->m_node_gen.add_node(node);

        m_flow_gen->m_node_gen.flush_file(c_stop_sec, d_time_flow, false, m_flow_gen, old_offset);

        if ( !m_flow_gen->is_terminated_by_master() && !go->preview.getNoCleanFlowClose() ) { // close gracefully
            m_flow_gen->m_node_gen.flush_file(-1, d_time_flow, true, m_flow_gen, old_offset);
        }
        m_flow_gen->flush_tx_queue();
        m_flow_gen->m_node_gen.close_file(m_flow_gen);
        m_flow_gen->m_c_tcp->cleanup_flows();
        m_flow_gen->m_s_tcp->cleanup_flows();
    } else {
        report_error(STARTUP_ID, "Could not sync DP thread for start, core ID: " + to_string(m_flow_gen->m_thread_id));
    }

    if ( m_state != STATE_TERMINATE ) {
        report_finished(STARTUP_ID);
        m_state = STATE_IDLE;
    }
}

void TrexAstfDpCore::start_tx_fif(uint32_t profile_id, double duration) {

    dsec_t d_time_flow;
    bool disable_client = false;
    double d_phase;

    m_flow_gen->switch_tcp_ctx(profile_id);
    get_scheduler_options(disable_client, d_time_flow, d_phase);

    CGenNode *node;

    if ( !disable_client ) {
        dsec_t now = now_sec();
        (void) duration;

        node = m_flow_gen->create_node();
        node->m_type = CGenNode::TCP_TX_FIF;
        node->m_time = now + d_phase + 0.1; /* phase the transmit a bit */
        m_flow_gen->m_node_gen.add_node(node);
    }
}

void TrexAstfDpCore::parse_astf_json(uint32_t profile_id, string *profile_buffer, string *topo_buffer) {
    TrexWatchDog::IOFunction dummy;
    (void)dummy;

    CAstfDB *db = CAstfDB::instance(profile_id);
    string err = "";
    bool rc;

    if ( topo_buffer ) {
        try {
            TopoMngr *topo_mngr = db->get_topo();
            topo_mngr->from_json_str(*topo_buffer);
            ClientCfgDB *m_cc_db = db->get_client_cfg_db();
            m_cc_db->load_from_topo(topo_mngr);
            //topo_mngr->dump();
        } catch (const TopoError &ex) {
            report_error(profile_id, ex.what());
            return;
        }
    }

    if ( !profile_buffer ) {
        report_finished(profile_id);
        return;
    }

    rc = db->set_profile_one_msg(*profile_buffer, err);
    if ( !rc ) {
        report_error(profile_id, "Profile parsing error: " + err);
        return;
    }

    // once we support specifying number of cores in start,
    // this should not be disabled by cache of profile hash
    int num_dp_cores = CGlobalInfo::m_options.preview.getCores() * CGlobalInfo::m_options.get_expected_dual_ports();
    CJsonData_err err_obj = db->verify_data(num_dp_cores);

    if ( err_obj.is_error() ) {
        report_error(profile_id, "Profile split to DP cores error: " + err_obj.description());
    } else {
        report_finished(profile_id);
    }
}

void TrexAstfDpCore::create_tcp_batch(uint32_t profile_id) {
    TrexWatchDog::IOFunction dummy;
    (void)dummy;

    /* jsmoon-TODO: duration should be set by profile_id */
    if (profile_id == 0) {
        CParserOption *go = &CGlobalInfo::m_options;

        m_flow_gen->m_cur_flow_id = 1;
        m_flow_gen->m_stats.clear();
        m_flow_gen->m_yaml_info.m_duration_sec = go->m_duration;
    }

    try {
        m_flow_gen->load_tcp_profile(profile_id);
    } catch (const TrexException &ex) {
        report_error(profile_id, "Could not create ASTF batch: " + string(ex.what()));
        return;
    }

    report_finished(profile_id);
}

void TrexAstfDpCore::delete_tcp_batch(uint32_t profile_id) {
    TrexWatchDog::IOFunction dummy;
    (void)dummy;

    m_flow_gen->unload_tcp_profile(profile_id);
    report_finished(profile_id);
}

void TrexAstfDpCore::start_transmit(uint32_t profile_id, double duration) {
    assert((m_state==STATE_IDLE) || (m_state==STATE_TRANSMITTING));
    if (m_state == STATE_IDLE) {
        m_state = STATE_TRANSMITTING;
        /* jsmoon-TODO: save profile_id/duration as start_scheduler() parameters */
    }
    else {
        start_tx_fif(profile_id, duration);
    }
}

void TrexAstfDpCore::stop_transmit(uint32_t profile_id) {
    if ( m_state == STATE_IDLE ) { // is stopped, just ack
        return;
    }
    /* jsmoon-TODO: trigger stopping TCP_TX_FIF only */

    add_global_duration(0.0001);
}

void TrexAstfDpCore::update_rate(uint32_t profile_id, double old_new_ratio) {
    m_flow_gen->switch_tcp_ctx(profile_id);
    m_flow_gen->m_c_tcp->m_fif_d_time *= old_new_ratio;
}

bool TrexAstfDpCore::sync_barrier() {
    return (m_flow_gen->get_sync_b()->sync_barrier(m_flow_gen->m_thread_id) == 0);
}

void TrexAstfDpCore::report_finished(uint32_t profile_id) {
    TrexDpToCpMsgBase *msg = new TrexDpCoreStopped(m_flow_gen->m_thread_id, profile_id);
    m_ring_to_cp->Enqueue((CGenNode *)msg);
}

void TrexAstfDpCore::report_error(uint32_t profile_id, const string &error) {
    TrexDpToCpMsgBase *msg = new TrexDpCoreError(m_flow_gen->m_thread_id, profile_id, error);
    m_ring_to_cp->Enqueue((CGenNode *)msg);
}

bool TrexAstfDpCore::rx_for_idle() {
    return m_flow_gen->handle_rx_pkts(true) > 0;
}


