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
#include "trex_astf_messaging.h"    /* TrexAstfDpStop */

#include "trex_astf.h"
#include "trex_astf_dp_core.h"
#include "trex_astf_topo.h"
#include "trex_client_config.h"


using namespace std;

TrexAstfDpCore::TrexAstfDpCore(uint8_t thread_id, CFlowGenListPerThread *core) :
                TrexDpCore(thread_id, core, STATE_IDLE) {
    m_start_param.m_flag = false;
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

void TrexAstfDpCore::add_profile_duration(uint32_t profile_id, double duration) {
    if (duration > 0.0) {
        CGenNodeCommand * node = (CGenNodeCommand*)m_core->create_node() ;

        node->m_type = CGenNode::COMMAND;

        /* make sure it will be scheduled after the current node */
        node->m_time = m_core->m_cur_time_sec + duration ;

        TrexAstfDpStop * cmd = new TrexAstfDpStop(profile_id);

        /* test this */
        m_core->m_non_active_nodes++;
        node->m_cmd = cmd;
        cmd->set_core_ptr(m_core);

        m_core->m_node_gen.add_node((CGenNode *)node);
    }
}

void TrexAstfDpCore::get_scheduler_options(uint32_t profile_id, bool& disable_client, dsec_t& d_time_flow, double& d_phase) {
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

    d_time_flow = m_flow_gen->m_c_tcp->get_fif_d_time(profile_id); /* set by Create_tcp function */

    d_phase = 0.01 + (double)m_flow_gen->m_thread_id * d_time_flow / (double)m_flow_gen->m_max_threads;

    if ( CGlobalInfo::is_realtime() ) {
        if (d_phase > 0.2 ) {
            d_phase =  0.01 + m_flow_gen->m_thread_id * 0.01;
        }
    }
}

void TrexAstfDpCore::start_scheduler() {

    uint32_t profile_id = 0;
    double duration = -1;

    if (m_start_param.m_flag) { /* set by start_transmit function */
        profile_id = m_start_param.m_profile_id;
        duration = m_start_param.m_duration;
    }

    dsec_t d_time_flow;
    bool disable_client = false;
    double d_phase;

    get_scheduler_options(profile_id, disable_client, d_time_flow, d_phase);

    CParserOption *go = &CGlobalInfo::m_options;

    double old_offset = 0.0;
    CGenNode *node;

    /* sync all core to the same time */
    if ( sync_barrier() ) {
        dsec_t now = now_sec();
        dsec_t c_stop_sec = -1;
        if ( duration > 0.0 ) {
            c_stop_sec = now + d_phase + duration;
        }
        else if ( m_flow_gen->m_yaml_info.m_duration_sec > 0 ) {
            c_stop_sec = now + d_phase + m_flow_gen->m_yaml_info.m_duration_sec;
        }

        m_flow_gen->m_cur_time_sec = now;

        if ( !disable_client ) {
            node = m_flow_gen->create_node();
            node->m_type = CGenNode::TCP_TX_FIF;
            node->m_time = now + d_phase + 0.1; /* phase the transmit a bit */
            node->m_ctx_id = profile_id; /* = tcp ctx id */
            m_flow_gen->m_node_gen.add_node(node);
        }

        m_flow_gen->m_c_tcp->activate(profile_id);
        m_flow_gen->m_s_tcp->activate(profile_id);
        if (c_stop_sec > 0.0) {
            add_profile_duration(profile_id, c_stop_sec - now);
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

        m_flow_gen->m_node_gen.flush_file(-1, d_time_flow, false, m_flow_gen, old_offset);

        if ( !m_flow_gen->is_terminated_by_master() && !go->preview.getNoCleanFlowClose() ) { // close gracefully
            m_flow_gen->m_node_gen.flush_file(-1, d_time_flow, true, m_flow_gen, old_offset);
        }
        m_flow_gen->flush_tx_queue();
        m_flow_gen->m_node_gen.close_file(m_flow_gen);
        m_flow_gen->m_c_tcp->cleanup_flows();
        m_flow_gen->m_s_tcp->cleanup_flows();
    } else {
        report_error(profile_id, "Could not sync DP thread for start, core ID: " + to_string(m_flow_gen->m_thread_id));
    }

    if ( m_state != STATE_TERMINATE ) {
        //report_finished(profile_id);
        m_state = STATE_IDLE;
    }
}

void TrexAstfDpCore::start_tcp_ctx(uint32_t profile_id, double duration) {

    dsec_t d_time_flow;
    bool disable_client = false;
    double d_phase;

    get_scheduler_options(profile_id, disable_client, d_time_flow, d_phase);

    dsec_t now = now_sec();

    m_flow_gen->m_cur_time_sec = now;

    if ( !disable_client ) {
        CGenNode *node = m_flow_gen->create_node();

        node->m_type = CGenNode::TCP_TX_FIF;
        node->m_time = now + d_phase + 0.1; /* phase the transmit a bit */
        node->m_ctx_id = profile_id; /* = tcp ctx id */
        m_flow_gen->m_node_gen.add_node(node);
    }

    m_flow_gen->m_c_tcp->activate(profile_id);
    m_flow_gen->m_s_tcp->activate(profile_id);
    if ( duration > 0 ) {
        add_profile_duration(profile_id, d_phase + duration);
    }
}

void TrexAstfDpCore::stop_tcp_ctx(uint32_t profile_id) {
    m_flow_gen->flush_tx_queue();

    m_flow_gen->m_c_tcp->cleanup_flows(profile_id);
    m_flow_gen->m_s_tcp->cleanup_flows(profile_id);

    m_flow_gen->m_c_tcp->deactivate(profile_id);
    m_flow_gen->m_s_tcp->deactivate(profile_id);

    report_finished(profile_id);

    if (m_flow_gen->m_c_tcp->active_profile_cnt() == 0) {
        add_global_duration(0.0001);
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

    CParserOption *go = &CGlobalInfo::m_options;

#if 0
    m_flow_gen->m_cur_flow_id = 1;      /* not used in ASTF mode */
    m_flow_gen->m_stats.clear();        /* needs to be global */
#endif
    m_flow_gen->m_yaml_info.m_duration_sec = go->m_duration;

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

        /* save profile_id/duration as start_scheduler() parameters */
        m_start_param.m_flag = true;
        m_start_param.m_profile_id = profile_id;
        m_start_param.m_duration = duration;
    }
    else {
        start_tcp_ctx(profile_id, duration);
    }
}

void TrexAstfDpCore::stop_transmit(uint32_t profile_id) {
    if ( m_state == STATE_IDLE ) { // is stopped, just ack
        return;
    }
    stop_tcp_ctx(profile_id);
}

void TrexAstfDpCore::update_rate(uint32_t profile_id, double old_new_ratio) {
    double fif_d_time = m_flow_gen->m_c_tcp->get_fif_d_time(profile_id);
    m_flow_gen->m_c_tcp->set_fif_d_time(fif_d_time*old_new_ratio, profile_id);
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


