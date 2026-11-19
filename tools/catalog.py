"""Extract documented CGMiner options; the running binary decides availability."""
import argparse, json, re
from pathlib import Path

def catalog(source):
    found = {}
    pattern = r'OPT_(WITH_ARG|WITHOUT_ARG|WITH_CBARG)\("([^"\n]+)"\s*,(.*?)\),'
    for match in re.finditer(pattern, source, re.S):
        flag, aliases, body = match.groups()
        names = re.findall(r'--([a-z0-9-]+)', aliases)
        if not names:
            continue
        name = names[0]
        # Keep the L3 and common options; unrelated ASIC driver settings are irrelevant.
        if name.startswith(('avalon', 'au3-', 'bab-', 'bfl', 'bitburner-', 'bmsc-', 'cointerra', 'drillbit', 'hashfast', 'hfa-', 'icarus-', 'klondike-', 'modminer-', 'rock-', 'usb-')):
            continue
        literals = re.findall(r'"((?:[^"\\]|\\.)*)"', body)
        description = ' '.join(literals) or 'Hidden source option; semantics depend on the firmware build.'
        kind = 'boolean' if flag == 'WITHOUT_ARG' else 'string'
        row = dict(name=name, kind=kind, description=description, group='Mining', source='Bitmain source', read_only=False, available=False)
        bounds = re.search(r'set_(int|float)_([0-9]+)_to_([0-9]+)', body)
        if bounds:
            row.update(kind='integer' if bounds[1]=='int' else 'number', min=int(bounds[2]), max=int(bounds[3]))
        if name.startswith('bitmain-'):
            row['group'] = 'Hardware'
        elif name.startswith('api-'):
            row['group'] = 'API'
        elif name.startswith('sched-'):
            row['group'] = 'Schedule'
        elif name.startswith('log') or 'debug' in name or name in ('verbose','quiet','real-quiet'):
            row['group'] = 'Diagnostics'
        # Never allow the web form to remove its own authentication/API connection,
        # spawn a shell command, load an external config, or alter shutdown protection.
        if name in ('monitor','include','config','version-file','default-config','api-host','api-port','api-allow','api-listen','api-network','api-groups','bitmain-notempoverctrl'):
            row['read_only'] = True
        if name not in found:
            found[name] = row
    return sorted(found.values(), key=lambda x:x['name'])

if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('source');p.add_argument('output');args=p.parse_args()
    rows=catalog(Path(args.source).read_text(encoding='utf-8',errors='replace'))
    Path(args.output).write_text(json.dumps(rows,indent=2)+'\n',encoding='utf-8')
    print(f'{len(rows)} source options catalogued; runtime availability is checked separately')
