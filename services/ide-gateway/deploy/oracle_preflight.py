#!/usr/bin/env python3
"""Read-only OCI inventory. Never creates resources or certifies a zero bill."""

import argparse
import json
import math
import os
import shutil
import subprocess
import sys


# Conservative planning ceilings from Oracle's public Always Free catalog.
# The console's actual entitlement and monthly consumption must also be checked.
CATALOG_URL = 'https://www.oracle.com/a/ocom/docs/oci-free-tier_v1.json'
CEILINGS = {
    'a1_ocpus': 2,
    'a1_memory_gb': 12,
    'volume_gb': 200,
    'total_volumes': 2,
    'vcns': 2,
}
PROPOSAL = {
    'shape': 'VM.Standard.A1.Flex',
    'a1_ocpus': 2,
    'a1_memory_gb': 12,
    'volume_gb': 50,
    'total_volumes': 1,
    'vcns': 1,
}
READ_COMMANDS = {
    ('iam', 'region-subscription', 'list'),
    ('iam', 'compartment', 'list'),
    ('iam', 'availability-domain', 'list'),
    ('compute', 'instance', 'list'),
    ('bv', 'boot-volume', 'list'),
    ('bv', 'volume', 'list'),
    ('network', 'vcn', 'list'),
}


class InventoryError(Exception):
    pass


def oci_read(command, *args):
    """Only the explicitly listed read operations can reach the OCI CLI."""
    if command not in READ_COMMANDS:
        raise InventoryError('Operação não permitida: esta ferramenta apenas consulta recursos.')
    try:
        result = subprocess.run(
            ['oci', *command, *args, '--output', 'json'],
            capture_output=True, text=True, timeout=60, check=True,
        )
        value = json.loads(result.stdout)
        if not isinstance(value, dict) or not isinstance(value.get('data'), list):
            raise ValueError('invalid list response')
        if any(not isinstance(row, dict) for row in value['data']):
            raise ValueError('invalid resource')
        return value['data']
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        # Do not emit CLI stderr: it may contain identifiers or profile paths.
        raise InventoryError('Consulta OCI falhou: ' + ' '.join(command)
                             + '. Inventário incompleto; não crie recursos com base nele.') from error


def positive(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InventoryError('Recurso com tamanho ausente ou inválido; inventário incompleto.')
    if not math.isfinite(value) or value <= 0:
        raise InventoryError('Recurso com tamanho ausente ou inválido; inventário incompleto.')
    return value


def lifecycle(resource):
    state = resource.get('lifecycle-state')
    if not isinstance(state, str) or not state:
        raise InventoryError('Recurso sem estado; inventário incompleto.')
    return state


def usage_of(instances, volumes, vcns):
    usage = dict.fromkeys(CEILINGS, 0)
    for instance in instances:
        # Count stopped and terminating instances conservatively: they may
        # restart, and an inventory snapshot is not a billing measurement.
        if lifecycle(instance) == 'TERMINATED':
            continue
        if not isinstance(instance.get('shape'), str) or not instance['shape']:
            raise InventoryError('Instância sem shape; inventário incompleto.')
        if instance['shape'] == 'VM.Standard.A1.Flex':
            config = instance.get('shape-config')
            if not isinstance(config, dict):
                raise InventoryError('Instância A1 sem tamanho; inventário incompleto.')
            usage['a1_ocpus'] += positive(config.get('ocpus'))
            usage['a1_memory_gb'] += positive(config.get('memory-in-gbs'))
    for volume in volumes:
        if lifecycle(volume) == 'TERMINATED':
            continue
        usage['volume_gb'] += positive(volume.get('size-in-gbs'))
        usage['total_volumes'] += 1
    for vcn in vcns:
        if lifecycle(vcn) != 'TERMINATED':
            usage['vcns'] += 1
    return usage


def inventory(tenancy, read=oci_read):
    subscriptions = read(('iam', 'region-subscription', 'list'),
                         '--tenancy-id', tenancy, '--all')
    homes = [r.get('region-name') for r in subscriptions if r.get('is-home-region') is True]
    if len(homes) != 1 or not isinstance(homes[0], str) or not homes[0]:
        raise InventoryError('Não foi possível identificar uma única região principal.')
    region = homes[0]
    common = ('--region', region, '--all')
    compartments = read(('iam', 'compartment', 'list'), '--compartment-id', tenancy,
                        '--compartment-id-in-subtree', 'true', '--access-level', 'ANY', *common)
    compartment_ids = {tenancy}
    for compartment in compartments:
        if lifecycle(compartment) == 'DELETED':
            continue
        if not isinstance(compartment.get('id'), str) or not compartment['id']:
            raise InventoryError('Compartimento sem identificador; inventário incompleto.')
        compartment_ids.add(compartment['id'])
    domains = read(('iam', 'availability-domain', 'list'), '--compartment-id', tenancy, *common)
    if not domains or any(not isinstance(d.get('name'), str) or not d['name'] for d in domains):
        raise InventoryError('Não foi possível listar os domínios de disponibilidade.')
    instances, volumes, vcns = [], [], []
    for compartment_id in sorted(compartment_ids):
        scope = ('--compartment-id', compartment_id, *common)
        instances.extend(read(('compute', 'instance', 'list'), *scope))
        volumes.extend(read(('bv', 'volume', 'list'), *scope))
        vcns.extend(read(('network', 'vcn', 'list'), *scope))
        for domain in domains:
            volumes.extend(read(('bv', 'boot-volume', 'list'),
                                '--availability-domain', domain['name'], *scope))
    usage = usage_of(instances, volumes, vcns)
    projected = {name: usage[name] + PROPOSAL[name] for name in CEILINGS}
    exceeded = [name for name in CEILINGS if projected[name] > CEILINGS[name]]
    return {
        'read_only': True,
        'inventory_complete': True,
        'home_region': region,
        'compartments_checked': len(compartment_ids),
        'current_usage': usage,
        'proposed_addition': PROPOSAL,
        'projected_usage': projected,
        'conservative_ceilings': CEILINGS,
        'exceeded': exceeded,
        'fits_planning_ceilings': not exceeded,
        'billing_verified': False,
        'capacity_verified': False,
        'catalog_reference': CATALOG_URL,
        'notice': ('Este relatório não comprova gratuidade nem disponibilidade. Confirme no painel '
                   'o plano Free Tier sem upgrade, a elegibilidade Always Free e o consumo mensal. '
                   'O teto de duas unidades de armazenamento é conservador e inclui discos de boot. '
                   'Nenhum recurso foi criado, alterado ou excluído.'),
    }


def main():
    parser = argparse.ArgumentParser(description='Consultar o inventário Oracle sem criar ou alterar recursos.')
    parser.add_argument('--tenancy-id', default=os.environ.get('OCI_TENANCY')
                        or os.environ.get('OCI_CLI_TENANCY'), help='OCID da conta; nunca uma chave ou senha.')
    args = parser.parse_args()
    try:
        if not shutil.which('oci'):
            raise InventoryError('Execute no Cloud Shell da Oracle, que já inclui o comando oci.')
        if not args.tenancy_id or not args.tenancy_id.startswith('ocid1.tenancy.'):
            raise InventoryError('Informe o OCID da conta com --tenancy-id, ou use OCI_TENANCY no Cloud Shell.')
        report = inventory(args.tenancy_id)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report['fits_planning_ceilings'] else 2
    except InventoryError as error:
        print(json.dumps({'read_only': True, 'inventory_complete': False,
                          'billing_verified': False, 'error': str(error)}, ensure_ascii=False, indent=2))
        return 2


if __name__ == '__main__':
    sys.exit(main())
