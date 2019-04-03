/*
 Itay Marom
 Hanoch Haim
 Cisco Systems, Inc.
*/

/*
Copyright (c) 2015-2016 Cisco Systems, Inc.

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
#ifndef __TREX_STL_MESSAGING_H__
#define __TREX_STL_MESSAGING_H__

#include "trex_messaging.h"
#include "trex_defs.h"


// create tcp batch per DP core
class TrexAstfDpCreateTcp : public TrexCpToDpMsgBase {
public:
    TrexAstfDpCreateTcp(uint32_t profile_id);
    TrexAstfDpCreateTcp() : TrexAstfDpCreateTcp(0) {}
    virtual TrexCpToDpMsgBase* clone();
    virtual bool handle(TrexDpCore *dp_core);
private:
    uint32_t m_profile_id;
};

// delete tcp batch per DP core
class TrexAstfDpDeleteTcp : public TrexCpToDpMsgBase {
public:
    TrexAstfDpDeleteTcp(uint32_t profile_id);
    TrexAstfDpDeleteTcp() : TrexAstfDpDeleteTcp(0) {}
    virtual TrexCpToDpMsgBase* clone();
    virtual bool handle(TrexDpCore *dp_core);
private:
    uint32_t m_profile_id;
};

/**
 * a message to start traffic
 *
 */
class TrexAstfDpStart : public TrexCpToDpMsgBase {
public:
    TrexAstfDpStart(uint32_t profile_id, double duration);
    TrexAstfDpStart() : TrexAstfDpStart(0, -1) {}
    virtual TrexCpToDpMsgBase* clone();
    virtual bool handle(TrexDpCore *dp_core);
private:
    uint32_t m_profile_id;
    double m_duration;
};

/**
 * a message to stop traffic
 *
 */
class TrexAstfDpStop : public TrexCpToDpMsgBase {
public:
    TrexAstfDpStop(uint32_t profile_id);
    TrexAstfDpStop() : TrexAstfDpStop(0) {}
    virtual TrexCpToDpMsgBase* clone();
    virtual bool handle(TrexDpCore *dp_core);
private:
    uint32_t m_profile_id;
};

/**
 * a message to update traffic rate
 *
 */
class TrexAstfDpUpdate : public TrexCpToDpMsgBase {
public:
    TrexAstfDpUpdate(uint32_t profile_id, double old_new_ratio);
    TrexAstfDpUpdate(double old_new_ratio) : TrexAstfDpUpdate(0, old_new_ratio) {}
    virtual TrexCpToDpMsgBase* clone();
    virtual bool handle(TrexDpCore *dp_core);
private:
    uint32_t m_profile_id;
    double m_old_new_ratio;
};

/**
 * a message to stop traffic
 *
 */
class TrexAstfLoadDB : public TrexCpToDpMsgBase {
public:
    TrexAstfLoadDB(uint32_t profile_id, std::string *profile_buffer, std::string *topo_buffer);
    TrexAstfLoadDB(std::string *profile_buffer, std::string *topo_buffer) : TrexAstfLoadDB(0, profile_buffer, topo_buffer) {}
    virtual TrexCpToDpMsgBase* clone();
    virtual bool handle(TrexDpCore *dp_core);
private:
    uint32_t m_profile_id;
    std::string *m_profile_buffer;
    std::string *m_topo_buffer;
};




#endif /* __TREX_STL_MESSAGING_H__ */

