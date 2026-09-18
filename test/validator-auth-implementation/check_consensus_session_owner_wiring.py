"""Require explicit P0 ownership without breaking legacy validator consensus."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
BRIDGE=(ROOT/'validator/consensus/bridge.cpp').read_text()
BUS=(ROOT/'validator/consensus/bus.h').read_text()
IFACE=(ROOT/'validator/interfaces/validator-manager.h').read_text()
MANAGER=(ROOT/'validator/manager.cpp').read_text()

def verify(bridge=BRIDGE,bus=BUS,iface=IFACE,manager=MANAGER):
    for token in (
        'get_validator_auth_session_owner',
        'start_bus(false, nullptr)',
        'if (resolved.required && !resolved.owner)',
        'start_bus(resolved.required, std::move(resolved.owner))',
        'if (authenticated_session_required && !authenticated_session)',
        'bus->authenticated_session_required = authenticated_session_required',
        'bus->authenticated_session = std::move(authenticated_session)',
    ):
        if token not in bridge: raise ValueError('bridge-'+token)
    for token in (
        'bool authenticated_session_required = false;',
        'std::shared_ptr<tos::auth::CommittedNativeSession> authenticated_session;',
    ):
        if token not in bus: raise ValueError('bus-'+token)
    for token in (
        'struct ValidatorAuthSessionOwnership',
        'bool required = false;',
        'get_validator_auth_session_owner(',
    ):
        if token not in iface: raise ValueError('interface-'+token)
    owner=manager[manager.index('void ValidatorManagerImpl::get_validator_auth_session_owner'):
                  manager.index('void ValidatorManagerImpl::establish_validator_auth_chain')]
    for token in (
        'native_session_binding_active(last_masterchain_state_->root_cell())',
        'ValidatorAuthSessionOwnership{false, nullptr}',
        'ValidatorAuthSessionOwnership{true, nullptr}',
        'ValidatorAuthSessionOwnership{true, it->second.owner}',
    ):
        if token not in owner: raise ValueError('manager-'+token)

def main():
    verify()
    probes = (
        (BRIDGE, 'start_bus(false, nullptr)', 'bridge'),
        (BRIDGE, 'if (resolved.required && !resolved.owner)', 'bridge'),
        (BRIDGE, 'if (authenticated_session_required && !authenticated_session)', 'bridge'),
        (BRIDGE, 'bus->authenticated_session_required = authenticated_session_required', 'bridge'),
        (MANAGER, 'ValidatorAuthSessionOwnership{false, nullptr}', 'manager'),
        (MANAGER, 'native_session_binding_active(last_masterchain_state_->root_cell())', 'manager'),
    )
    for source, token, kind in probes:
        changed=source.replace(token,'/* removed */',1)
        if changed==source:
            raise RuntimeError('negative control changed nothing '+token)
        try:
            if kind=='bridge': verify(bridge=changed)
            else: verify(manager=changed)
        except ValueError:
            pass
        else:
            raise RuntimeError('negative control survived '+token)
    print('PASS: legacy validators need no P0 owner, while active P0 validators require the manager-owned committed session')

if __name__=='__main__': main()
