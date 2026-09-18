"""Require validator consensus to hold the manager-owned committed session."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
BRIDGE=(ROOT/'validator/consensus/bridge.cpp').read_text()
BUS=(ROOT/'validator/consensus/bus.h').read_text()
IFACE=(ROOT/'validator/interfaces/validator-manager.h').read_text()

def verify(bridge=BRIDGE,bus=BUS,iface=IFACE):
    for token in ('get_validator_auth_session_owner','start_bus(nullptr)',
                  'refusing to construct validator bus without authenticated session owner',
                  'bus->authenticated_session = std::move(authenticated_session)'):
        if token not in bridge: raise ValueError('bridge-'+token)
    if 'std::shared_ptr<tos::auth::CommittedNativeSession> authenticated_session;' not in bus:
        raise ValueError('bus-owner')
    if 'get_validator_auth_session_owner(' not in iface:
        raise ValueError('manager-interface')
    ask=bridge.index('get_validator_auth_session_owner')
    start=bridge.index('start_bus(std::shared_ptr<tos::auth::CommittedNativeSession>')
    if ask > start:
        raise ValueError('owner-not-requested-before-validator-bus')

def main():
    verify()
    for token in ('get_validator_auth_session_owner',
                  'bus->authenticated_session = std::move(authenticated_session)',
                  'if (params_.local_id && !authenticated_session)'):
        changed=BRIDGE.replace(token,'/* removed */',1)
        try: verify(bridge=changed)
        except ValueError: pass
        else: raise RuntimeError('negative control survived '+token)
    print('PASS: validator consensus bus requires the manager-owned committed authenticated session')

if __name__=='__main__': main()
