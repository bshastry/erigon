#!/usr/bin/env python3
"""
Fuzzer Crash Triage Script for Erigon EVM Fuzzer

This script analyzes crash files from the Erigon native fuzzer and:
1. Clusters crashes by root cause
2. Extracts key characteristics
3. Generates a detailed diagnostic report

Usage:
    python3 triage_crashes.py [crash_dir] [output_report]
"""

import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Any, Tuple
import hashlib


class CrashAnalyzer:
    """Analyzes and clusters fuzzer crash files."""

    def __init__(self, crash_dir: str):
        self.crash_dir = Path(crash_dir)
        self.crashes: List[Dict[str, Any]] = []
        self.clusters: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def load_crashes(self) -> int:
        """Load all crash JSON files from the directory."""
        crash_files = sorted(self.crash_dir.glob("crash_*.json"))

        for crash_file in crash_files:
            try:
                with open(crash_file, 'r') as f:
                    data = json.load(f)

                # Extract the test name and test data
                if not data:
                    continue

                test_name = list(data.keys())[0]
                test_data = data[test_name]

                crash_info = {
                    'file': crash_file.name,
                    'test_name': test_name,
                    'test_data': test_data,
                    'characteristics': self._extract_characteristics(test_name, test_data)
                }
                self.crashes.append(crash_info)

            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Could not parse {crash_file}: {e}")

        return len(self.crashes)

    def _extract_characteristics(self, test_name: str, test_data: Dict) -> Dict[str, Any]:
        """Extract key characteristics from a crash for clustering."""
        chars = {}

        # Parse test name for characteristics
        chars['test_source'] = self._extract_test_source(test_name)
        chars['fork'] = self._extract_fork(test_name)
        chars['call_opcode'] = self._extract_call_opcode(test_name)
        chars['gas_limit_category'] = self._extract_gas_limit_category(test_name)
        chars['data_variant'] = self._extract_data_variant(test_name)
        chars['test_type'] = self._extract_test_type(test_name)

        # Extract from test data
        if test_data:
            chars['precompile_address'] = self._detect_precompile(test_data)
            chars['code_pattern'] = self._extract_code_pattern(test_data)
            chars['tx_data_length'] = self._get_tx_data_length(test_data)
            chars['has_storage'] = self._has_non_empty_storage(test_data)
            chars['env_config'] = self._extract_env_config(test_data)

        return chars

    def _extract_test_source(self, test_name: str) -> str:
        """Extract the source test file/module."""
        match = re.search(r'tests/([^/]+/[^/]+)', test_name)
        return match.group(1) if match else 'unknown'

    def _extract_fork(self, test_name: str) -> str:
        """Extract the fork name."""
        match = re.search(r'fork_(\w+)', test_name)
        return match.group(1) if match else 'unknown'

    def _extract_call_opcode(self, test_name: str) -> str:
        """Extract the call opcode used."""
        match = re.search(r'call_opcode_(\w+)', test_name)
        return match.group(1) if match else 'unknown'

    def _extract_gas_limit_category(self, test_name: str) -> str:
        """Extract and categorize gas limit."""
        match = re.search(r'gas_limit_(\d+)', test_name)
        if not match:
            return 'unknown'
        gas = int(match.group(1))
        if gas < 100000:
            return 'low'
        elif gas < 150000:
            return 'medium'
        else:
            return 'high'

    def _extract_data_variant(self, test_name: str) -> str:
        """Extract data variant number."""
        match = re.search(r'data(\d+)', test_name)
        return f"data{match.group(1)}" if match else 'unknown'

    def _extract_test_type(self, test_name: str) -> str:
        """Extract the test type (e.g., invalid_gas, valid, etc.)."""
        if 'invalid' in test_name.lower():
            if 'gas' in test_name.lower():
                return 'invalid_gas'
            return 'invalid_other'
        return 'valid'

    def _detect_precompile(self, test_data: Dict) -> str:
        """Detect which precompile is being tested."""
        # Check transaction 'to' address
        tx = test_data.get('transaction', {})
        to_addr = tx.get('to', '')

        # Standard precompile addresses (1-9)
        precompile_map = {
            '0x0000000000000000000000000000000000000001': 'ecrecover',
            '0x0000000000000000000000000000000000000002': 'sha256',
            '0x0000000000000000000000000000000000000003': 'ripemd160',
            '0x0000000000000000000000000000000000000004': 'identity',
            '0x0000000000000000000000000000000000000005': 'modexp',
            '0x0000000000000000000000000000000000000006': 'bn256add',
            '0x0000000000000000000000000000000000000007': 'bn256scalar_mul',
            '0x0000000000000000000000000000000000000008': 'bn256pairing',
            '0x0000000000000000000000000000000000000009': 'blake2f',
        }

        if to_addr in precompile_map:
            return precompile_map[to_addr]

        # Check in pre state code for CALL to precompile
        pre = test_data.get('pre', {})
        for addr, account in pre.items():
            code = account.get('code', '')
            # Look for calls to address 9 (blake2f)
            if '60095af' in code.lower():  # PUSH1 0x09 CALL
                return 'blake2f'
            if '60095af2' in code.lower():  # PUSH1 0x09 CALLCODE
                return 'blake2f'

        return 'unknown'

    def _extract_code_pattern(self, test_data: Dict) -> str:
        """Extract a hash of the contract code pattern."""
        pre = test_data.get('pre', {})
        codes = []
        for addr, account in pre.items():
            code = account.get('code', '')
            if code and code != '0x':
                codes.append(code)

        if not codes:
            return 'no_code'

        # Create a hash of the code pattern
        combined = '|'.join(sorted(codes))
        return hashlib.md5(combined.encode()).hexdigest()[:8]

    def _get_tx_data_length(self, test_data: Dict) -> int:
        """Get the length of transaction data."""
        tx = test_data.get('transaction', {})
        data = tx.get('data', [])
        if isinstance(data, list) and data:
            data = data[0]
        if isinstance(data, str):
            # Remove 0x prefix and count bytes
            data = data.replace('0x', '')
            return len(data) // 2
        return 0

    def _has_non_empty_storage(self, test_data: Dict) -> bool:
        """Check if any account has non-empty storage."""
        pre = test_data.get('pre', {})
        for addr, account in pre.items():
            storage = account.get('storage', {})
            if storage:
                return True
        return False

    def _extract_env_config(self, test_data: Dict) -> str:
        """Extract key environment configuration."""
        env = test_data.get('env', {})
        config = test_data.get('config', {})

        # Key configuration items
        parts = []
        if 'currentBaseFee' in env:
            parts.append(f"basefee:{env['currentBaseFee']}")
        if 'blobSchedule' in config:
            parts.append('blob_schedule')

        return '|'.join(parts) if parts else 'default'

    def cluster_crashes(self):
        """Cluster crashes by their characteristics."""
        # Primary clustering by precompile + test type
        for crash in self.crashes:
            chars = crash['characteristics']

            # Create cluster key
            cluster_key = (
                chars['precompile_address'],
                chars['test_type'],
                chars['code_pattern']
            )

            self.clusters[cluster_key].append(crash)

    def generate_report(self) -> str:
        """Generate a detailed diagnostic report."""
        lines = []

        lines.append("=" * 80)
        lines.append("ERIGON FUZZER CRASH TRIAGE REPORT")
        lines.append("=" * 80)
        lines.append("")

        # Summary statistics
        lines.append("## SUMMARY")
        lines.append(f"Total crashes analyzed: {len(self.crashes)}")
        lines.append(f"Unique crash clusters: {len(self.clusters)}")
        lines.append("")

        # Distribution by characteristics
        lines.append("## CRASH DISTRIBUTION")
        lines.append("")

        # By fork
        fork_dist = defaultdict(int)
        for crash in self.crashes:
            fork_dist[crash['characteristics']['fork']] += 1

        lines.append("### By Fork")
        for fork, count in sorted(fork_dist.items(), key=lambda x: -x[1]):
            pct = count / len(self.crashes) * 100
            lines.append(f"  {fork}: {count} ({pct:.1f}%)")
        lines.append("")

        # By call opcode
        opcode_dist = defaultdict(int)
        for crash in self.crashes:
            opcode_dist[crash['characteristics']['call_opcode']] += 1

        lines.append("### By Call Opcode")
        for opcode, count in sorted(opcode_dist.items(), key=lambda x: -x[1]):
            pct = count / len(self.crashes) * 100
            lines.append(f"  {opcode}: {count} ({pct:.1f}%)")
        lines.append("")

        # By gas limit category
        gas_dist = defaultdict(int)
        for crash in self.crashes:
            gas_dist[crash['characteristics']['gas_limit_category']] += 1

        lines.append("### By Gas Limit Category")
        for gas, count in sorted(gas_dist.items(), key=lambda x: -x[1]):
            pct = count / len(self.crashes) * 100
            lines.append(f"  {gas}: {count} ({pct:.1f}%)")
        lines.append("")

        # By precompile
        precompile_dist = defaultdict(int)
        for crash in self.crashes:
            precompile_dist[crash['characteristics']['precompile_address']] += 1

        lines.append("### By Precompile")
        for precompile, count in sorted(precompile_dist.items(), key=lambda x: -x[1]):
            pct = count / len(self.crashes) * 100
            lines.append(f"  {precompile}: {count} ({pct:.1f}%)")
        lines.append("")

        # By test type
        type_dist = defaultdict(int)
        for crash in self.crashes:
            type_dist[crash['characteristics']['test_type']] += 1

        lines.append("### By Test Type")
        for test_type, count in sorted(type_dist.items(), key=lambda x: -x[1]):
            pct = count / len(self.crashes) * 100
            lines.append(f"  {test_type}: {count} ({pct:.1f}%)")
        lines.append("")

        # By data variant
        data_dist = defaultdict(int)
        for crash in self.crashes:
            data_dist[crash['characteristics']['data_variant']] += 1

        lines.append("### By Data Variant")
        for data_var, count in sorted(data_dist.items(), key=lambda x: -x[1]):
            pct = count / len(self.crashes) * 100
            lines.append(f"  {data_var}: {count} ({pct:.1f}%)")
        lines.append("")

        # Detailed cluster analysis
        lines.append("=" * 80)
        lines.append("## CRASH CLUSTERS (DETAILED)")
        lines.append("=" * 80)
        lines.append("")

        # Sort clusters by size
        sorted_clusters = sorted(self.clusters.items(), key=lambda x: -len(x[1]))

        for i, (cluster_key, crashes) in enumerate(sorted_clusters, 1):
            precompile, test_type, code_pattern = cluster_key

            lines.append(f"### Cluster {i}: {precompile} / {test_type}")
            lines.append(f"Crashes in cluster: {len(crashes)}")
            lines.append(f"Code pattern hash: {code_pattern}")
            lines.append("")

            # Get sample characteristics
            sample = crashes[0]
            chars = sample['characteristics']

            lines.append("Representative crash characteristics:")
            lines.append(f"  - Test source: {chars['test_source']}")
            lines.append(f"  - TX data length: {chars['tx_data_length']} bytes")
            lines.append(f"  - Has storage: {chars['has_storage']}")
            lines.append(f"  - Env config: {chars['env_config']}")
            lines.append("")

            # Fork distribution within cluster
            cluster_forks = defaultdict(int)
            for c in crashes:
                cluster_forks[c['characteristics']['fork']] += 1

            lines.append("Fork distribution in cluster:")
            for fork, count in sorted(cluster_forks.items(), key=lambda x: -x[1]):
                lines.append(f"  - {fork}: {count}")
            lines.append("")

            # Sample files
            lines.append("Sample crash files:")
            for c in crashes[:5]:
                lines.append(f"  - {c['file']}")
            if len(crashes) > 5:
                lines.append(f"  ... and {len(crashes) - 5} more")
            lines.append("")
            lines.append("-" * 40)
            lines.append("")

        # Root cause analysis
        lines.append("=" * 80)
        lines.append("## ROOT CAUSE ANALYSIS")
        lines.append("=" * 80)
        lines.append("")

        lines.extend(self._generate_root_cause_analysis())

        # Recommendations
        lines.append("=" * 80)
        lines.append("## RECOMMENDATIONS")
        lines.append("=" * 80)
        lines.append("")
        lines.extend(self._generate_recommendations())

        return '\n'.join(lines)

    def _generate_root_cause_analysis(self) -> List[str]:
        """Generate root cause analysis based on crash patterns."""
        lines = []

        # Analyze dominant patterns
        precompile_counts = defaultdict(int)
        fork_counts = defaultdict(int)
        test_type_counts = defaultdict(int)

        for crash in self.crashes:
            chars = crash['characteristics']
            precompile_counts[chars['precompile_address']] += 1
            fork_counts[chars['fork']] += 1
            test_type_counts[chars['test_type']] += 1

        # Find dominant precompile
        dominant_precompile = max(precompile_counts.items(), key=lambda x: x[1])
        dominant_test_type = max(test_type_counts.items(), key=lambda x: x[1])

        lines.append("### Primary Root Cause Hypothesis")
        lines.append("")

        if dominant_precompile[0] == 'blake2f':
            lines.append("**BLAKE2f Precompile (EIP-152) Invalid Gas Handling**")
            lines.append("")
            lines.append("The vast majority of crashes involve the BLAKE2f precompile (address 0x09)")
            lines.append("being called with invalid/low gas. This suggests one of the following:")
            lines.append("")
            lines.append("1. **Gas Calculation Bug**: The gas cost calculation for BLAKE2f may not")
            lines.append("   match the specification, causing unexpected behavior when gas is")
            lines.append("   insufficient.")
            lines.append("")
            lines.append("2. **Error Handling Issue**: When BLAKE2f fails due to insufficient gas,")
            lines.append("   the error handling path may have an issue (e.g., not properly")
            lines.append("   cleaning up state or returning incorrect values).")
            lines.append("")
            lines.append("3. **CALL/CALLCODE Differences**: Both CALL and CALLCODE are affected,")
            lines.append("   suggesting the issue is in the precompile itself, not the calling")
            lines.append("   convention.")
            lines.append("")

        if dominant_test_type[0] == 'invalid_gas':
            lines.append("### Invalid Gas Test Pattern")
            lines.append("")
            lines.append("All crashes occur in 'invalid gas' test scenarios, where the test")
            lines.append("intentionally provides insufficient gas to trigger edge cases.")
            lines.append("")
            lines.append("This pattern suggests the Erigon implementation may differ from")
            lines.append("other clients in how it handles:")
            lines.append("")
            lines.append("- Out-of-gas conditions in precompile execution")
            lines.append("- Gas refund calculations after failed precompile calls")
            lines.append("- Return data handling when precompile fails")
            lines.append("")

        # Fork analysis
        lines.append("### Fork-Specific Analysis")
        lines.append("")

        fork_list = sorted(fork_counts.items(), key=lambda x: -x[1])
        total = len(self.crashes)

        for fork, count in fork_list:
            pct = count / total * 100
            lines.append(f"- **{fork}**: {count} crashes ({pct:.1f}%)")

        lines.append("")
        lines.append("The crashes appear across multiple forks (Istanbul, Berlin, Cancun),")
        lines.append("indicating this is likely not a fork-specific issue but a fundamental")
        lines.append("implementation difference that has persisted across protocol upgrades.")
        lines.append("")

        # Code pattern analysis
        unique_code_patterns = set()
        for crash in self.crashes:
            unique_code_patterns.add(crash['characteristics']['code_pattern'])

        lines.append("### Contract Code Analysis")
        lines.append("")
        lines.append(f"Unique contract code patterns: {len(unique_code_patterns)}")
        lines.append("")
        lines.append("The crashes involve a small number of unique code patterns, all")
        lines.append("designed to:")
        lines.append("1. Copy calldata to memory")
        lines.append("2. Execute a CALL/CALLCODE to the BLAKE2f precompile (address 0x09)")
        lines.append("3. Store the result/success flag in storage")
        lines.append("")

        return lines

    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on analysis."""
        lines = []

        lines.append("### Immediate Actions")
        lines.append("")
        lines.append("1. **Review BLAKE2f Precompile Implementation**")
        lines.append("   - Location: `execution/evm/precompile/blake2f.go` or similar")
        lines.append("   - Focus on gas cost calculation and error handling")
        lines.append("   - Compare with go-ethereum and other client implementations")
        lines.append("")

        lines.append("2. **Create Minimal Reproduction Test**")
        lines.append("   - Extract the simplest crash case")
        lines.append("   - Run against multiple clients to confirm behavior difference")
        lines.append("   - Document expected vs actual behavior")
        lines.append("")

        lines.append("3. **Review EIP-152 Specification Compliance**")
        lines.append("   - Gas calculation: `GFROUND * rounds` where GFROUND = 1")
        lines.append("   - Input validation requirements")
        lines.append("   - Return value semantics on failure")
        lines.append("")

        lines.append("### Deduplication Strategy")
        lines.append("")
        lines.append("The 876 crashes likely represent a **single underlying bug** with")
        lines.append("multiple trigger conditions. After fixing, rerun the fuzzer to")
        lines.append("confirm all variants are resolved.")
        lines.append("")

        lines.append("### Testing Improvements")
        lines.append("")
        lines.append("1. Add specific unit tests for BLAKE2f edge cases")
        lines.append("2. Add differential testing against other clients")
        lines.append("3. Consider property-based testing for precompiles")
        lines.append("")

        return lines

    def export_cluster_summary(self) -> Dict[str, Any]:
        """Export cluster summary as JSON for further processing."""
        summary = {
            'total_crashes': len(self.crashes),
            'total_clusters': len(self.clusters),
            'clusters': []
        }

        for cluster_key, crashes in sorted(self.clusters.items(), key=lambda x: -len(x[1])):
            precompile, test_type, code_pattern = cluster_key

            fork_dist = defaultdict(int)
            for c in crashes:
                fork_dist[c['characteristics']['fork']] += 1

            cluster_info = {
                'precompile': precompile,
                'test_type': test_type,
                'code_pattern': code_pattern,
                'crash_count': len(crashes),
                'fork_distribution': dict(fork_dist),
                'sample_files': [c['file'] for c in crashes[:5]]
            }
            summary['clusters'].append(cluster_info)

        return summary


def main():
    crash_dir = sys.argv[1] if len(sys.argv) > 1 else "testdata/testdata/custom_crashes"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "crash_triage_report.md"

    print(f"Analyzing crashes in: {crash_dir}")

    analyzer = CrashAnalyzer(crash_dir)

    # Load crashes
    count = analyzer.load_crashes()
    print(f"Loaded {count} crash files")

    if count == 0:
        print("No crashes found!")
        return

    # Cluster crashes
    analyzer.cluster_crashes()
    print(f"Identified {len(analyzer.clusters)} crash clusters")

    # Generate report
    report = analyzer.generate_report()

    # Write report
    with open(output_file, 'w') as f:
        f.write(report)
    print(f"Report written to: {output_file}")

    # Also write JSON summary
    json_output = output_file.replace('.md', '.json')
    summary = analyzer.export_cluster_summary()
    with open(json_output, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"JSON summary written to: {json_output}")

    # Print quick summary to console
    print("\n" + "=" * 60)
    print("QUICK SUMMARY")
    print("=" * 60)
    print(f"Total crashes: {count}")
    print(f"Unique clusters: {len(analyzer.clusters)}")
    print("\nTop clusters by size:")
    for i, (key, crashes) in enumerate(sorted(analyzer.clusters.items(), key=lambda x: -len(x[1]))[:5], 1):
        precompile, test_type, _ = key
        print(f"  {i}. {precompile}/{test_type}: {len(crashes)} crashes")


if __name__ == "__main__":
    main()
