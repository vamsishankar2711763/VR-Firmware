import os
import re
import matplotlib.pyplot as plt
from datetime import datetime

def expand_config_variant(entry):
    if "{" in entry and "}" in entry:
        base, variant = re.match(r"(.*?)\{(.*?)\}", entry).groups()
        return [base, base + variant]
    return [entry]

def check_flag_presence(content, flag):
    if isinstance(flag, dict) and "require_all" in flag:
        return all(is_flag_enabled(content, f) for f in flag["require_all"])
    elif isinstance(flag, tuple):
        return any(is_flag_enabled(content, f) for f in flag)
    elif "{" in flag:
        variants = expand_config_variant(flag)
        return any(is_flag_enabled(content, v) for v in variants)
    else:
        return is_flag_enabled(content, flag)

def is_flag_enabled(content, flag):
    pattern_enabled = re.compile(rf"^\s*{re.escape(flag)}=y", re.MULTILINE)
    pattern_disabled = re.compile(rf"^\s*#\s*{re.escape(flag)} is not set", re.MULTILINE)
    if pattern_disabled.search(content):
        return False
    return pattern_enabled.search(content) is not None

def analyze_config_file(filepath, config_flags):
    with open(filepath, "r", errors="ignore") as f:
        content = f.read().replace("-", "_")
    missing_flags = []
    for flag in config_flags:
        if not check_flag_presence(content, flag):
            missing_flags.append(str(flag))
    return missing_flags

def scan_q3_configs(directory="."):
    config_flags = [
        ("CONFIG_HAVE_STACKPROTECTOR", "CONFIG_STACKPROTECTOR", "CONFIG_STACKPROTECTOR_STRONG", "CONFIG_CC_STACKPROTECTOR"),
        "CONFIG_RANDOMIZE_BASE",
        "CONFIG_SLAB_FREELIST_RANDOM",
        "CONFIG_HARDENED_USERCOPY",
        ("CONFIG_ARCH_HAS_FORTIFY_SOURCE", "CONFIG_FORTIFY_SOURCE"),
        ("CONFIG_ARCH_HAS_STRICT_KERNEL_RWX", "CONFIG_DEBUG_RODATA"),
        ("CONFIG_CPU_SW_DOMAIN_PAN", "CONFIG_ARM64_SW_TTBR0_PAN"),
        "CONFIG_UNMAP_KERNEL_AT_EL0",
        "CONFIG_CFI_CLANG",
        ("CONFIG_SHADOW_CALL_STACK","CONFIG_ARCH_SUPPORTS_SHADOW_CALL_STACK","CONFIG_CC_HAVE_SHADOW_CALL_STACK"),
        ("CONFIG_INIT_STACK_ALL", "CONFIG_INIT_STACK_ALL_ZERO"),
        "CONFIG_INIT_ON_ALLOC_DEFAULT_ON",
        "CONFIG_DEBUG_LIST",
        "CONFIG_BPF_JIT_ALWAYS_ON",
        "CONFIG_SLAB_FREELIST_HARDENED",
        "CONFIG_VMAP_STACK",
        "CONFIG_ARM64_UAO"
    ]

    devices = {
        'q1': {'dates': [], 'mitigations': [], 'missing': []},
        'q2': {'dates': [], 'mitigations': [], 'missing': []},
        'q3': {'dates': [], 'mitigations': [], 'missing': []},
        'qpro': {'dates': [], 'mitigations': [], 'missing': []}
    }

    for filename in sorted(os.listdir(directory)):
        print(f"Processing file: {filename}")
        match_q1 = re.match(r"q1_v\d+_(\d{2}-\d{2}-\d{4})", filename)
        match_q2 = re.match(r"q2_v\d+_(\d{2}-\d{2}-\d{4})", filename)
        match_q3 = re.match(r"q3_v\d+_(\d{2}-\d{2}-\d{4})", filename)
        match_qpro = re.match(r"QPro_v\d+_(\d{2}-\d{2}-\d{4})", filename)

        matched = match_q1 or match_q2 or match_q3 or match_qpro
        if matched:
            date_str = matched.group(1)
            date_obj = datetime.strptime(date_str, "%m-%d-%Y")
            path = os.path.join(directory, filename)
            missing = analyze_config_file(path, config_flags)
            applied = len(config_flags) - len(missing)

            if match_q1:
                device = 'q1'
            elif match_q2:
                device = 'q2'
            elif match_q3:
                device = 'q3'
            else:
                device = 'qpro'

            devices[device]['dates'].append(date_obj)
            devices[device]['mitigations'].append(applied)
            devices[device]['missing'].append((filename, missing))
    
    return (
        devices['q1']['dates'], devices['q1']['mitigations'], devices['q1']['missing'],
        devices['q2']['dates'], devices['q2']['mitigations'], devices['q2']['missing'],
        devices['q3']['dates'], devices['q3']['mitigations'], devices['q3']['missing'],
        devices['qpro']['dates'], devices['qpro']['mitigations'], devices['qpro']['missing'],
    )

def plot_mitigations():
    # Baseline
    dates = [
        datetime(2019, 1, 1),
        datetime(2019, 7, 7),
        datetime(2019, 9, 15),
        datetime(2025, 1, 1)
    ]
    mitigations = [15, 16, 17, 17]
    plt.plot(dates, mitigations, label="Baseline Mitigations", color='purple', marker='o', linestyle='-', linewidth=2)

    # Pico 4
    dates_line1 = [
        datetime(2023, 1, 7),
        datetime(2023, 2, 17),
        datetime(2024, 3, 2),
        datetime(2024, 9, 12),
        datetime(2024,12,12)
    ]
    mitigations_line1 = [11, 11, 11, 11,11]
    plt.step(dates_line1, mitigations_line1, where='post', label="Pico 4 Mitigations", color='brown', marker='x', linewidth=2)

    # Pico 3
    dates_line2 = [
        datetime(2022, 8, 22),
        datetime(2022, 12, 23),
        datetime(2024, 3, 2),
        datetime(2024, 9, 10),
        datetime(2024,12,12)
    ]
    mitigations_line2 = [11, 11, 11, 11,11]
    plt.step(dates_line2, mitigations_line2, where='post', label="Pico 3 Neo", color='gray', marker='s', linewidth=2)

def print_missing(missing, label):
    print(f"\n=== Missing Mitigations for {label} ===")
    for fname, flags in missing:
        print(f"{fname}: {len(flags)} missing → {flags}")

# Run analysis
(
    dates_q1, mitigations_q1, missing_q1,
    dates_q2, mitigations_q2, missing_q2,
    dates_q3, mitigations_q3, missing_q3,
    dates_qpro, mitigations_qpro, missing_qpro
) = scan_q3_configs(".")

# Sort for plotting
sorted_dates_q1, sorted_mitigations_q1 = zip(*sorted(zip(dates_q1, mitigations_q1))) if dates_q1 else ([], [])
sorted_dates_q2, sorted_mitigations_q2 = zip(*sorted(zip(dates_q2, mitigations_q2))) if dates_q2 else ([], [])
sorted_dates_q3, sorted_mitigations_q3 = zip(*sorted(zip(dates_q3, mitigations_q3))) if dates_q3 else ([], [])
sorted_dates_qpro, sorted_mitigations_qpro = zip(*sorted(zip(dates_qpro, mitigations_qpro))) if dates_qpro else ([], [])

# Plotting
plt.figure(figsize=(10, 6))
plot_mitigations()

if sorted_dates_q1:
    plt.plot(sorted_dates_q1, sorted_mitigations_q1, color='b', label='Q1 Mitigations Applied', marker='o')
if sorted_dates_q2:
    plt.plot(sorted_dates_q2, sorted_mitigations_q2, color='orange', label='Q2 Mitigations Applied', marker='o')
if sorted_dates_q3:
    plt.plot(sorted_dates_q3, sorted_mitigations_q3, color='g', label='Q3 Mitigations Applied', marker='o')
if sorted_dates_qpro:
    plt.plot(sorted_dates_qpro, sorted_mitigations_qpro, color='r', label='QPro Mitigations Applied', marker='o')

plt.xticks(rotation=45)
plt.gca().xaxis.set_major_formatter(plt.matplotlib.dates.DateFormatter('%Y'))
plt.gca().xaxis.set_major_locator(plt.matplotlib.dates.YearLocator())
plt.xlabel('Year')
plt.ylabel('Number of Mitigations Applied')
plt.title('Mitigations Applied Over Time')
plt.tight_layout()
plt.legend()
plt.show()

# Print missing mitigations
print_missing(missing_q1, "Quest 1")
print_missing(missing_q2, "Quest 2")
print_missing(missing_q3, "Quest 3")
print_missing(missing_qpro, "Quest Pro")
