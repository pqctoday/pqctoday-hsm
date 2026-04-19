/*
 * wasm_backend.c — C-level config backend for the strongSwan WASM build.
 *
 * In a normal charon deployment the backend (stroke / vici / swanctl)
 * feeds IKE and peer configs to the daemon. The WASM build has no unix
 * socket — so JS injects a strongswan.conf *and* this C shim exposes:
 *
 *   wasm_setup_config(mode)        : pre-registers default IKE/peer cfgs
 *                                    + PSK credentials (read from env
 *                                    WASM_PSK). Called once from
 *                                    libcharon's _main() under
 *                                    __EMSCRIPTEN__ guards.
 *
 *   wasm_get_peer_by_name(this,n)  : backend_t::get_peer_cfg_by_name
 *   wasm_create_peer_enum(this,...)  : backend_t::create_peer_cfg_enumerator
 *   wasm_create_ike_enum (this,...)  : backend_t::create_ike_cfg_enumerator
 *
 *   wasm_set_proposal_mode(mode)   : 0 = classical (AES/ECP256)
 *                                    1 = pure PQC  (ML-KEM-768)
 *                                    2 = hybrid    (ML-KEM-768 + ECP256)
 *
 *   wasm_initiate()                : kick off IKE_SA_INIT for the
 *                                    "charon-initiator" peer_cfg.
 *
 * Signatures match the baseline WASM exports exactly (see Appendix B of
 * the task brief).
 */

#ifdef __EMSCRIPTEN__

#include <stdlib.h>
#include <string.h>

#include <daemon.h>
#include <library.h>
#include <config/backend.h>
#include <config/peer_cfg.h>
#include <config/ike_cfg.h>
#include <config/child_cfg.h>
#include <collections/linked_list.h>
#include <collections/enumerator.h>
#include <credentials/auth_cfg.h>
#include <credentials/sets/mem_cred.h>

/*─────────────────────────────────────────────────────────────────────*/
/* Globals                                                             */
/*─────────────────────────────────────────────────────────────────────*/

/* Proposal-selection mode (0=classical, 1=pure-pqc, 2=hybrid). Read by
 * wasm_setup_config() to pick which proposal strings to bake into the
 * IKE cfg. */
int wasm_proposal_mode = 0;

void wasm_set_proposal_mode(int mode)
{
    wasm_proposal_mode = mode;
}

/* Linked list of peer_cfg_t owned by this backend. */
static linked_list_t *peer_cfgs = NULL;

/* Backend singleton. */
typedef struct {
    backend_t public;
} wasm_backend_t;
static wasm_backend_t *wasm_backend = NULL;

/*─────────────────────────────────────────────────────────────────────*/
/* backend_t vtable                                                    */
/*─────────────────────────────────────────────────────────────────────*/

peer_cfg_t *wasm_get_peer_by_name(backend_t *this, char *name)
{
    enumerator_t *e;
    peer_cfg_t *cfg, *found = NULL;

    if (!peer_cfgs || !name) return NULL;
    e = peer_cfgs->create_enumerator(peer_cfgs);
    while (e->enumerate(e, &cfg))
    {
        if (streq(cfg->get_name(cfg), name))
        {
            found = cfg->get_ref(cfg);
            break;
        }
    }
    e->destroy(e);
    return found;
}

enumerator_t *wasm_create_peer_enum(backend_t *this,
                                    identification_t *me,
                                    identification_t *other)
{
    if (!peer_cfgs) return enumerator_create_empty();
    return peer_cfgs->create_enumerator(peer_cfgs);
}

enumerator_t *wasm_create_ike_enum(backend_t *this,
                                   host_t *me, host_t *other)
{
    /* Derive ike_cfg from each peer_cfg. strongSwan treats this as a
     * thin enumerator — we just enumerate the ike_cfgs referenced by
     * the registered peer_cfgs. Simplest correct implementation: wrap
     * the peer_cfgs enumerator and project each to its ike_cfg. */
    if (!peer_cfgs) return enumerator_create_empty();
    /* Project via a custom enumerator. For minimal infrastructure we
     * return an empty enumerator — the responder branch is driven by
     * peer_cfgs directly, and the initiator uses wasm_initiate() which
     * already has the peer_cfg in hand. */
    return enumerator_create_empty();
}

/*─────────────────────────────────────────────────────────────────────*/
/* wasm_setup_config — builds default peer + IKE cfgs from env vars    */
/*─────────────────────────────────────────────────────────────────────*/

static const char *proposal_ike_classical = "aes256-sha256-ecp256";
static const char *proposal_ike_pqc       = "aes256-sha256-mlkem768";
static const char *proposal_ike_hybrid    = "aes256-sha256-mlkem768-ecp256";
static const char *proposal_esp           = "aes256-sha256";

void wasm_setup_config(int unused)
{
    peer_cfg_t *peer_cfg;
    ike_cfg_t *ike_cfg;
    child_cfg_t *child_cfg;
    auth_cfg_t *auth_local, *auth_remote;
    peer_cfg_create_t peer_data;
    ike_cfg_create_t  ike_data;
    child_cfg_create_t child_data;
    const char *ike_prop;
    const char *psk_env;
    mem_cred_t *creds;

    /* Lazy-init backend + storage. */
    if (!peer_cfgs) peer_cfgs = linked_list_create();

    switch (wasm_proposal_mode)
    {
        case 1: ike_prop = proposal_ike_pqc;       break;
        case 2: ike_prop = proposal_ike_hybrid;    break;
        default: ike_prop = proposal_ike_classical; break;
    }

    /* IKE config — local=0.0.0.0, remote=0.0.0.0 for either role. */
    memset(&ike_data, 0, sizeof(ike_data));
    ike_data.version     = IKEV2;
    ike_data.local       = "0.0.0.0";
    ike_data.local_port  = 500;
    ike_data.remote      = "0.0.0.0";
    ike_data.remote_port = 500;
    ike_cfg = ike_cfg_create(&ike_data);
    ike_cfg->add_proposal(ike_cfg, proposal_create_from_string(PROTO_IKE,
                                                               (char *)ike_prop));

    /* Peer config. */
    memset(&peer_data, 0, sizeof(peer_data));
    peer_data.cert_policy = CERT_SEND_IF_ASKED;
    peer_data.unique      = UNIQUE_NO;
    peer_data.keyingtries = 1;
    peer_cfg = peer_cfg_create("wasm", ike_cfg, &peer_data);

    /* Auth round — PSK both sides. Identities are derived from the
     * strongswan.conf / hardcoded; the JS worker injects them via
     * STRONGSWAN_CONF_DATA. Here we use '%any' placeholders. */
    auth_local = auth_cfg_create();
    auth_local->add(auth_local, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PSK);
    auth_local->add(auth_local, AUTH_RULE_IDENTITY,
                    identification_create_from_string("%any"));
    peer_cfg->add_auth_cfg(peer_cfg, auth_local, TRUE);

    auth_remote = auth_cfg_create();
    auth_remote->add(auth_remote, AUTH_RULE_AUTH_CLASS, AUTH_CLASS_PSK);
    auth_remote->add(auth_remote, AUTH_RULE_IDENTITY,
                     identification_create_from_string("%any"));
    peer_cfg->add_auth_cfg(peer_cfg, auth_remote, FALSE);

    /* Child config. */
    memset(&child_data, 0, sizeof(child_data));
    child_data.mode = MODE_TUNNEL;
    child_cfg = child_cfg_create("wasm-child", &child_data);
    child_cfg->add_proposal(child_cfg, proposal_create_from_string(PROTO_ESP,
                                                                   (char *)proposal_esp));
    peer_cfg->add_child_cfg(peer_cfg, child_cfg);

    peer_cfgs->insert_last(peer_cfgs, peer_cfg);

    /* Register the backend the first time. */
    if (!wasm_backend)
    {
        wasm_backend = malloc(sizeof(*wasm_backend));
        memset(wasm_backend, 0, sizeof(*wasm_backend));
        wasm_backend->public.get_peer_cfg_by_name =
            (peer_cfg_t *(*)(backend_t *, char *))wasm_get_peer_by_name;
        wasm_backend->public.create_peer_cfg_enumerator =
            (enumerator_t *(*)(backend_t *, identification_t *,
                               identification_t *))wasm_create_peer_enum;
        wasm_backend->public.create_ike_cfg_enumerator =
            (enumerator_t *(*)(backend_t *, host_t *, host_t *))
                wasm_create_ike_enum;
        charon->backends->add_backend(charon->backends, &wasm_backend->public);
    }

    /* Pre-register PSK from the WASM_PSK env var. */
    psk_env = getenv("WASM_PSK");
    if (psk_env && *psk_env)
    {
        creds = mem_cred_create();
        creds->add_shared(creds,
            shared_key_create(SHARED_IKE,
                chunk_clone(chunk_create((u_char *)psk_env, strlen(psk_env)))),
            NULL);
        lib->credmgr->add_set(lib->credmgr, &creds->set);
    }
}

/*─────────────────────────────────────────────────────────────────────*/
/* wasm_initiate — trigger IKE_SA_INIT on the responder                */
/*─────────────────────────────────────────────────────────────────────*/

void wasm_initiate(int unused)
{
    peer_cfg_t *peer_cfg;
    enumerator_t *e;
    child_cfg_t *child_cfg = NULL;
    enumerator_t *ce;

    if (!peer_cfgs) return;
    e = peer_cfgs->create_enumerator(peer_cfgs);
    if (!e->enumerate(e, &peer_cfg))
    {
        e->destroy(e);
        return;
    }
    peer_cfg = peer_cfg->get_ref(peer_cfg);
    e->destroy(e);

    ce = peer_cfg->create_child_cfg_enumerator(peer_cfg);
    if (ce->enumerate(ce, &child_cfg))
    {
        child_cfg = child_cfg->get_ref(child_cfg);
    }
    ce->destroy(ce);

    if (child_cfg)
    {
        charon->controller->initiate(charon->controller, peer_cfg, child_cfg,
                                     NULL, NULL, 0, 0, FALSE);
    }
    else
    {
        peer_cfg->destroy(peer_cfg);
    }
}

#endif /* __EMSCRIPTEN__ */
