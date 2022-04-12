//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// sunlit.cc 

#include "detection/detection_engine.h"
#include "events/event_queue.h"
#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "main/snort_debug.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include <fstream>
#include <string>
#include "torch/script.h"
#include <iostream>



using namespace snort;

#define SUNLIT_GID 256
#define SUNLIT_SID 2

static const char* s_name = "sunlit";
static const char* s_help = "Sunlit Deep Learning Inspector";

static THREAD_LOCAL ProfileStats sunlitPerfStats;

static THREAD_LOCAL SimpleStats sunlitstats;

THREAD_LOCAL const Trace* sunlit_trace = nullptr;


//-------------------------------------------------------------------------
// class stuff
//-------------------------------------------------------------------------

class Sunlit : public Inspector
{
public:

    void show(const SnortConfig*) const override;
    void eval(Packet*) override;
    

private:
    bool to_hex(char* dest, size_t dest_len, const uint8_t* values, size_t val_len);
};



void Sunlit::show(const SnortConfig*) const
{

}

bool Sunlit::to_hex(char* dest, size_t dest_len, const uint8_t* values, size_t val_len) {

    if(dest_len < (val_len*2+1)) /* check that dest is large enough */
        return false;
    
    *dest = '\0'; /* in case val_len==0 */
    while(val_len--) {
        /* sprintf directly to where dest points */
        sprintf(dest, "%02X", *values);
        dest += 2;
        ++values;
    }
    return true;
}

void Sunlit::eval(Packet* p)
{

    torch::jit::script::Module module;
    //try {
        // Deserialize the ScriptModule from a file using torch::jit::load().
        module = torch::jit::load("traced_resnet_model.pt");
        WarningMessage("ok");
        return;
        // Create a vector of inputs.
        std::vector<torch::jit::IValue> inputs;
        inputs.push_back(torch::ones({1, 3, 224, 224}));

        // Execute the model and turn its output into a tensor.
        at::Tensor output = module.forward(inputs).toTensor();
        std::cout << output.slice(/*dim=*/1, /*start=*/0, /*end=*/5) << '\n';


   // }
  //  catch (const c10::Error& e) {
  //      WarningMessage("error loading the model");
        
   //     return;
  //  }

    WarningMessage("ok");
    return;
    WarningMessage("start");
    

    char buffer[p->pktlen*2+1]; /* one extra for \0 */

    
    if(to_hex(buffer, sizeof(buffer), p->pkt, p->pktlen))
    {
        std::fstream myfile;
        myfile = std::fstream("file.hex", std::fstream::out | std::fstream::app);
        myfile.write(buffer, strlen(buffer));
    }


    trace_logf(sunlit_trace, p, "destination port: %d, packet payload size: %d.\n",
        p->ptrs.dp, p->dsize);
    DetectionEngine::queue_event(SUNLIT_GID, SUNLIT_SID);


    ++sunlitstats.total_packets;
    //WarningMessage("destination port: %d, packet payload size: %d.\n",
    //        p->ptrs.dp, p->dsize);
}

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const RuleMap sunlit_rules[] =
{
    { SUNLIT_SID, "too much data sent to port" },
    { 0, nullptr }
};

class SunlitModule : public Module
{
public:
    SunlitModule() : Module(s_name, s_help)
    { }

    unsigned get_gid() const override
    { return SUNLIT_GID; }

    const RuleMap* get_rules() const override
    { return sunlit_rules; }

    const PegInfo* get_pegs() const override
    { return simple_pegs; }

    PegCount* get_counts() const override
    { return (PegCount*)&sunlitstats; }

    ProfileStats* get_profile() const override
    { return &sunlitPerfStats; }

    Usage get_usage() const override
    { return INSPECT; }

    void set_trace(const Trace*) const override;
    const TraceOption* get_trace_options() const override;


};


void SunlitModule::set_trace(const Trace* trace) const
{ sunlit_trace = trace; }

const TraceOption* SunlitModule::get_trace_options() const
{
    static const TraceOption sunlit_options(nullptr, 0, nullptr);
    return &sunlit_options;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new SunlitModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Inspector* sunlit_ctor(Module* m)
{
    SunlitModule* mod = (SunlitModule*)m;
    return new Sunlit;
}

static void sunlit_dtor(Inspector* p)
{
    delete p;
}

static const InspectApi sunlit_api
{
    {
        PT_INSPECTOR,
        sizeof(InspectApi),
        INSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    IT_PROBE,
    PROTO_BIT__ANY_IP | PROTO_BIT__ETH,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    sunlit_ctor,
    sunlit_dtor,
    nullptr, // ssn
    nullptr  // reset
};

SO_PUBLIC const BaseApi* snort_plugins[] =
{
    &sunlit_api.base,
    nullptr
};

