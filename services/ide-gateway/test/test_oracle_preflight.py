import importlib.util
import pathlib
import unittest


script = pathlib.Path(__file__).parents[1] / 'deploy' / 'oracle_preflight.py'
spec = importlib.util.spec_from_file_location('oracle_preflight', script)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class OraclePreflightTest(unittest.TestCase):
    def test_stopped_instances_and_detached_disks_still_count(self):
        usage = preflight.usage_of([
            {'shape': 'VM.Standard.A1.Flex', 'lifecycle-state': 'STOPPED',
             'shape-config': {'ocpus': 1, 'memory-in-gbs': 6}},
            {'lifecycle-state': 'TERMINATED'},
        ], [{'lifecycle-state': 'AVAILABLE', 'size-in-gbs': 180},
            {'lifecycle-state': 'TERMINATED'}], [{'lifecycle-state': 'AVAILABLE'}])
        self.assertEqual(usage, {'a1_ocpus': 1, 'a1_memory_gb': 6, 'volume_gb': 180,
                                 'total_volumes': 1, 'vcns': 1})

    def test_unknown_sizes_and_states_do_not_count_as_zero(self):
        for invalid in (None, True, -1, 0, float('nan'), float('inf'), '50'):
            with self.subTest(invalid=invalid), self.assertRaises(preflight.InventoryError):
                preflight.usage_of([], [{'lifecycle-state': 'AVAILABLE', 'size-in-gbs': invalid}], [])
        with self.assertRaises(preflight.InventoryError):
            preflight.usage_of([{'shape': 'VM.Standard.A1.Flex', 'lifecycle-state': 'RUNNING'}], [], [])
        with self.assertRaises(preflight.InventoryError):
            preflight.usage_of([{'shape': '', 'lifecycle-state': 'RUNNING'}], [], [])
        with self.assertRaises(preflight.InventoryError):
            preflight.usage_of([], [], [{}])

    def reader(self, denied=False, extra_disk=False):
        calls = []

        def read(command, *args):
            calls.append((command, args))
            if command == ('iam', 'region-subscription', 'list'):
                return [{'region-name': 'sa-saopaulo-1', 'is-home-region': True},
                        {'region-name': 'us-ashburn-1', 'is-home-region': False}]
            self.assertEqual(args[args.index('--region') + 1], 'sa-saopaulo-1')
            if command == ('iam', 'compartment', 'list'):
                return [{'id': 'child', 'lifecycle-state': 'ACTIVE'}]
            if command == ('iam', 'availability-domain', 'list'):
                return [{'name': 'domain-one'}, {'name': 'domain-two'}]
            compartment = args[args.index('--compartment-id') + 1]
            if denied and compartment == 'child':
                raise preflight.InventoryError('Acesso negado; inventário incompleto.')
            if extra_disk and command == ('bv', 'boot-volume', 'list') and compartment == 'child':
                if args[args.index('--availability-domain') + 1] == 'domain-two':
                    return [{'lifecycle-state': 'AVAILABLE', 'size-in-gbs': 175}]
            return []

        return read, calls

    def test_uses_home_region_all_compartments_and_all_domains(self):
        read, calls = self.reader()
        report = preflight.inventory('root', read)
        self.assertTrue(report['fits_planning_ceilings'])
        self.assertFalse(report['billing_verified'])
        self.assertFalse(report['capacity_verified'])
        boot_calls = [(c, a) for c, a in calls if c == ('bv', 'boot-volume', 'list')]
        self.assertEqual(len(boot_calls), 4)
        self.assertNotIn('root', str(report))
        self.assertNotIn('child', str(report))

    def test_cannot_hide_other_compartment_disks_or_access_denials(self):
        read, _ = self.reader(extra_disk=True)
        report = preflight.inventory('root', read)
        self.assertFalse(report['fits_planning_ceilings'])
        self.assertIn('volume_gb', report['exceeded'])
        read, _ = self.reader(denied=True)
        with self.assertRaises(preflight.InventoryError):
            preflight.inventory('root', read)

    def test_unknown_home_region_and_mutations_are_rejected(self):
        with self.assertRaises(preflight.InventoryError):
            preflight.inventory('root', lambda *args: [])
        with self.assertRaises(preflight.InventoryError):
            preflight.oci_read(('compute', 'instance', 'launch'))


if __name__ == '__main__':
    unittest.main()
